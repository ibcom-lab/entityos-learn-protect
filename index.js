/*
	ENTITYOS PROTECT API / FACTORY
	
	https://storage.api.entityos,cloud

	(For Future)
	node_modules/protectfactory/

	References:
	https://aws - kms

	"protect-data-encrypt"
	"protect-data-decrypt"
	
	Depends on;
	https://learn.entityos.cloud/learn-function-automation

	---

	This is a lambda compliant node app with a wrapper to process data from API Gateway & respond to it.

	To run it on your local computer your need to install
	https://www.npmjs.com/package/lambda-local and then run as:

	lambda-local -l index.js -t 9000 -e event.json

	API Gateway docs:
	- https://docs.aws.amazon.com/lambda/latest/dg/nodejs-handler.html
	
	Authentication:
	Get apikey in the event data, and using user in settings.json get the username based on matching GUID
	The use the authKey in the event data as the password with the username.
	!! In production make sure the settings.json is unrestricted data with functional restriction to setup_user
	!!! The apiKey user has restricted data (based on relationships) and functional access

	Event Data:
	{
	  "body": {
	    "apikey": "e7849d3a-d8a3-49c7-8b27-70b85047e0f1"
	  },
	  "queryStringParameters": {},
	  "headers": {}
	}

	event/passed data available via request contect in the app scope.
	eg
		var request = entityos.get(
		{
			scope: 'app',
			context: 'request'
		});

		{ 
			body: {},
			queryString: {},
			headers: {}
		}

	"app-auth" checks the apikey sent against users in the space (as per settings.json)
	
	Run:
	lambda-local -l index.js -t 9000 -e event-learn-protect-data-encrypt-lab.json
	lambda-local -l index.js -t 9000 -e event-learn-protect-data-decrypt-lab.json
	
	Upload to AWS Lambda:
	zip -r ../entityos-learn-protect-DDMMMYYYY-n.zip *
*/

exports.handler = function (event, context, callback)
{
	var entityos = require('entityos');
	var _ = require('lodash')
	var moment = require('moment');
	var entityosProtect = require('entityos/entityos.protect.js');

	entityos._util.message(event)

	if (event.isBase64Encoded)
	{
		event.body = Buffer.from(event.body, 'base64').toString('utf-8');
	}

	console.log(event)

	if (_.isString(event.body))
	{
		if (_.startsWith(event.body, 'ey'))
		{
			event.body = JSON.parse(Buffer.from(event.body, 'base64').toString('utf-8'));
		}
		else
		{
			event.body = JSON.parse(event.body);
		}
	}

	if (_.isString(event.body.data))
	{
		if (_.startsWith(event.body.data, 'ey'))
		{
			event.body.data = JSON.parse(Buffer.from(event.body, 'base64').toString('utf-8'));
		}
		else
		{
			event.body.data = JSON.parse(event.body.data);
		}
	}

	if (_.has(event, 'body._context'))
	{
		event.context = event.body._context;
	}

	entityos.set(
	{
		scope: '_event',
		value: event
	});

	entityos.set(
	{
		scope: '_context',
		value: context
	});

	/*
		Use promise to responded to API Gateway once all the processing has been completed.
	*/

	const promise = new Promise(function(resolve, reject)
	{	
		entityos.init(main);
		//main();

		function main(err, data)
		{
			/*
				app initialises with entityos.invoke('app-init') after controllers added.
			*/

			entityos.add(
			{
				name: 'app-init',
				code: function ()
				{
					entityos._util.message('Using entityos module version ' + entityos.VERSION);
					entityos._util.message(entityos.data.session);

					var eventData = entityos.get(
					{
						scope: '_event'
					});

					var request =
					{ 
						body: {},
						queryString: {},
						headers: {}
					}

					if (eventData != undefined)
					{
						request.queryString = eventData.queryStringParameters;
						request.headers = eventData.headers;

						if (_.isString(eventData.body))
						{
							request.body = JSON.parse(eventData.body)
						}
						else
						{
							request.body = eventData.body;
						}	
					}

					if (request.headers['x-api-key'] != undefined)
					{
						var _xAPIKey = _.split(request.headers['x-api-key'], '|');
						
						if (_xAPIKey.length == 0)
						{
							entityos.invoke('util-end', {error: 'Bad x-api-key in header [' + request.headers['x-api-key'] + '] - it should be {apiKey} or {apiKey}|{authKey}.'}, '401');
						}
						else
						{
							if (_xAPIKey.length == 1)
							{
								request.body.apikey = _xAPIKey[0];
							}
							else
							{
								request.body.apikey = _xAPIKey[0];
								request.body.authkey = _xAPIKey[1];
							}
						}
					}

					entityos.set({scope: '_data', value: request.body.data})

					if (request.headers['x-auth-key'] != undefined)
					{
						request.body.authkey = request.headers['x-auth-key'];
					}

					entityos.set(
					{
						scope: '_request',
						value: request
					});

					if (request.body.apikey != undefined)
					{
						if (request.body.authkey != undefined)
						{
							entityos.invoke('app-auth');
						}
						else
						{
							if (request.body.method == 'app-process-ssi-get-specs')
							{
								entityos.invoke('app-start');
							}
							else
							{
								entityos.invoke('util-end', {error: 'Missing authKey'}, '401');
							}
						}
					}
					else
					{
						entityos.invoke('app-start');
					}
				}
			});

			entityos.add(
			{
				name: 'app-auth',
				code: function (param)
				{
					var request = entityos.get(
					{
						scope: '_request'
					});

					var requestApiKeyGUID = request.body.apikey;

					entityos.cloud.search(
					{
						object: 'setup_user',
						fields: [{name: 'username'}],
						filters:
						[
							{
								field: 'guid',
								comparison: 'EQUAL_TO',
								value: requestApiKeyGUID
							}
						],
						callback: 'app-auth-process'
					});
				}
			});

			entityos.add(
			{
				name: 'app-auth-process',
				code: function (param, response)
				{
					entityos.set(
					{
						scope: 'app',
						context: 'user',
						value: response
					});

					if (response.status == 'ER')
					{
						entityos.invoke('util-end', {error: 'Error processing user authentication.'}, '401');
					}
					else
					{
						if (response.data.rows.length == 0)
						{
							var request = entityos.get(
							{
								scope: '_request'
							});

							var requestApiKeyGUID = request.body.apikey;

							entityos.invoke('util-end', {error: 'Bad apikey [' + requestApiKeyGUID + ']'}, '401');
						}
						else
						{
							var user = _.first(response.data.rows);

							var request = entityos.get(
							{
								scope: '_request'
							});

							var requestAuthKeyGUID = request.body.authkey;

							entityos.logon('app-auth-logon-process',
							{
								logon: user.username,
								password: requestAuthKeyGUID
							});
						}
					}
				}
			});

			entityos.add(
			{
				name: 'app-auth-logon-process',
				code: function (response)
				{
					if (response.status == 'ER')
					{
						var request = entityos.get(
						{
							scope: '_request'
						});

						var requestAuthKeyGUID = request.body.authkey;

						if (response.error.errornotes == 'LogonKey has not been requested')
						{
							entityos.invoke('util-end', {error: 'Bad authkey user config. Set authenticationlevel=1. [' + requestAuthKeyGUID + ']'}, '401');
						}
						else
						{
							entityos.invoke('util-end', {error: 'Bad authkey [' + requestAuthKeyGUID + ']'}, '401');
						}
					}
					else
					{
						entityos.set(
						{
							scope: 'app',
							context: 'user',
							value: response
						});

						entityos.invoke('app-user');
					}
				}
			});

			entityos.add(
			{
				name: 'app-user',
				code: function (param)
				{
					entityos.cloud.invoke(
					{
						method: 'core_get_user_details',
						callback: 'app-user-process'
					});
				}
			});

			entityos.add(
			{
				name: 'app-user-process',
				code: function (param, response)
				{
					entityos.set(
					{
						scope: 'app',
						context: 'user',
						value: response
					})

					entityos.invoke('app-start')
				}
			});

			entityos.add(
			{
				name: 'util-uuid',
				code: function (param)
				{
					var pattern = entityos._util.param.get(param, 'pattern', {"default": 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'}).value;
					var scope = entityos._util.param.get(param, 'scope').value;
					var context = entityos._util.param.get(param, 'context').value;

					var uuid = pattern.replace(/[xy]/g, function(c) {
						    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
						    return v.toString(16);
						  });

					entityos.set(
					{
						scope: scope,
						context: context,
						value: uuid
					})
				}
			});

			entityos.add(
			{
				name: 'app-log',
				code: function ()
				{
					var eventData = entityos.get(
					{
						scope: '_event'
					});

					entityos.cloud.invoke(
					{
						object: 'core_debug_log',
						fields:
						{
							data: JSON.stringify(eventData),
							notes: 'app Log (Event)'
						}
					});

					var requestData = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					entityos.cloud.invoke(
					{
						object: 'core_debug_log',
						fields:
						{
							data: JSON.stringify(requestData),
							notes: 'app Log (Request)'
						}
					});

					var contextData = entityos.get(
					{
						scope: '_context'
					});

					entityos.cloud.invoke(
					{
						object: 'core_debug_log',
						fields:
						{
							data: JSON.stringify(contextData),
							notes: 'appLog (Context)'
						},
						callback: 'app-log-saved'
					});
				}
			});

			entityos.add(
			{
				name: 'app-log-saved',
				code: function (param, response)
				{
					entityos._util.message('Log data saved to entityos.cloud');
					entityos._util.message(param);
					entityos._util.message(response);
				
					entityos.invoke('app-respond')
				}
			});

			entityos.add(
			{
				name: 'app-respond',
				code: function (param)
				{
					var response = entityos.get(
					{
						scope: 'app',
						context: 'response'
					});

					var statusCode = response.httpStatus;
					if (statusCode == undefined) {statusCode = '200'}

					var body = response.data;
					if (body == undefined) {body = {}}
					
					var headers = response.headers;
					if (headers == undefined) {headers = {}}

					let httpResponse =
					{
						statusCode: statusCode,
						headers: headers,
						body: JSON.stringify(body)
					};

					resolve(httpResponse)
				}
			});

			entityos.add(
			{
				name: 'util-end',
				code: function (data, statusCode, headers)
				{
					if (statusCode == undefined) { statusCode = '200' }
					if (headers == undefined) { headers = {'Content-Type': 'application/json'} }

					entityos.set(
					{
						scope: 'app',
						context: 'response',
						value:
						{
							data: data,
							statusCode: statusCode,
							headers: headers
						}
					});

					entityos.invoke('app-respond')
				}
			});

			entityos.add(
			{
				name: 'app-start',
				code: function ()
				{
					var request = entityos.get(
					{
						scope: '_request'
					});

					var data = request.body;
					var mode = data.mode;
					var method = data.method;

					if (_.isString(mode))
					{
						mode = {type: mode, status: 'OK'}
					}

					if (mode == undefined)
					{
						mode = {type: 'live', status: 'OK'}
					}

					if (mode.status == undefined)
					{
						mode.status = 'OK';
					}

					mode.status = mode.status.toUpperCase();

					if (mode.type == 'reflect')
					{
						var response = {}

						if (mode.data != undefined)
						{
							response.data = mode.data;
						}
						
						entityos.invoke('util-uuid',
						{
							scope: 'guid',
							context: 'log'
						});

						entityos.invoke('util-uuid',
						{
							scope: 'guid',
							context: 'audit'
						});

						response.data = _.assign(response.data,
						{
							status: mode.status,
							method: method,
							reflected: data,
							guids: entityos.get(
							{
								scope: 'guid'
							})
						});

						entityos.set(
						{
							scope: 'app',
							context: 'response',
							value: response
						});

						entityos.invoke('app-respond');
					}
					else
					{
						entityos.invoke('app-process');
					}
				}
			});

			//-- METHODS

			entityos.add(
			{
				name: 'app-process',
				code: function ()
				{
					var request = entityos.get(
					{
						scope: '_request'
					});

					var data = request.body;

					var method = data.method;
	
					if (_.includes(
					[
						'protect-data-encrypt',
						'protect-data-decrypt',
						'protect-data-hash'
					],
						method))
					{
						entityos.invoke('app-process-' + method)
					}
					else
					{
						entityos.set(
						{
							scope: 'app',
							context: 'response',
							value:
							{
								status: 'ER',
								data: {error: {code: '2', description: 'Not a valid method [' + method + ']'}}
							}
						});

						entityos.invoke('app-respond');
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-storage-protect-data-encrypt',
				code: function ()
				{
					var request = entityos.get(
					{
						scope: '_request'
					});

					var data = request.body.data;

					if (data == undefined)
					{
						entityos.invoke('util-end', 
						{
							error: 'Missing data.'
						},
						'403');
					}
					else
					{
						const settings = entityos.get({scope: '_settings'});
						var dataToEncrypt = _.get(data, 'encrypt')

						if (dataToEncrypt == undefined)
						{
							entityos.invoke('util-end', 
							{
								error: 'No data to encrypt [encrypt].'
							},
							'403');
						}
						else
						{
							const encryptionService = _.get(data, 'service', 'default');

							if (encryptionService == 'default')
							{
								const keys = _.get(settings, 'protect.keys');
								const keyHash = _.get(event, 'keyhash'); //hash of the sha256/base58 "key";

								let _key;

								if (keyHash == undefined)
								{
									_key = _.find(keys, function (key)
									{
										return key.default
									});

									if (_key != undefined)
									{
										_key.keyHash = entityosProtect.hash({text: _key.key, output: 'base58'}).textHashed;
									}
								}
								else
								{
									_key = _.find(keys, function (key)
									{
										return key.keyhash == keyHash;
									});
								}

								if (_key == undefined)
								{
									entityos.invoke('util-end',
									{
										method: 'storage-protect-data-encrypt',
										status: 'ER',
										data: {error: 'Key not found'}
									},
									'401');
								}
								else
								{
									if (_.isString(dataToEncrypt))
									{
										dataToEncypt = [dataToEncrypt]
									}

									console.log(dataToEncrypt);

									let dataToEncryptProcessed = [];

									_.each(dataToEncrypt, function (_dataToEncrypt)
									{
										if (_.isString(_dataToEncrypt))
										{
											dataToEncryptProcessed.push(
											{
												data: _dataToEncrypt,
												encrypted: 	entityosProtect.encrypt(
												{
													text: _dataToEncrypt,
													key: _key.key,
													iv: _key.iv
												}).textEncrypted
											})
										}
										else
										{
											_dataToEncrypt.encrypted = entityosProtect.encrypt(
											{
												text: _dataToEncrypt.data,
												key: _key.key,
												iv: _key.iv
											}).textEncrypted;

											dataToEncryptProcessed.push(_dataToEncrypt);
										}
									});
							
									if (_key.id == undefined)
									{
										_key.id = _.truncate(_key.keyhash, {length: 6});
									}

									var responseData =
									{
										"encrypted": dataToEncryptProcessed,
										"keyhash": _key.keyHash,
										"keyid": _key.id
									}

									entityos.invoke('util-end',
									{
										method: 'storage-protect-data-encrypt',
										status: 'OK',
										data: responseData
									},
									'200');
								}
							}
						}
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-storage-protect-data-decrypt',
				code: function ()
				{
					var request = entityos.get(
					{
						scope: '_request'
					});

					var data = request.body.data;

					if (data == undefined)
					{
						entityos.invoke('util-end', 
						{
							error: 'Missing data.'
						},
						'403');
					}
					else
					{
						const settings = entityos.get({scope: '_settings'});
						var dataToDecrypt = _.get(data, 'decrypt')

						if (dataToDecrypt == undefined)
						{
							entityos.invoke('util-end', 
							{
								error: 'No data to encrypt [decrypt].'
							},
							'403');
						}
						else
						{
							const encryptionService = _.get(data, 'service', 'default');

							if (encryptionService == 'default')
							{
								const keys = _.get(settings, 'protect.keys');
								const keyHash = _.get(event, 'keyhash'); //hash of the sha256/base58 "key";

								let _key;

								if (keyHash == undefined)
								{
									_key = _.find(keys, function (key)
									{
										return key.default
									});

									if (_key != undefined)
									{
										_key.keyHash = entityosProtect.hash({text: _key.key, output: 'base58'}).textHashed;
									}
								}
								else
								{
									_key = _.find(keys, function (key)
									{
										return key.keyhash == keyHash;
									});
								}

								if (_key == undefined)
								{
									entityos.invoke('util-end',
									{
										method: 'storage-protect-data-decrypt',
										status: 'ER',
										data: {error: 'Key not found'}
									},
									'401');
								}
								else
								{
									if (_.isString(dataToDecrypt))
									{
										dataToDecrypt = [dataToDecrypt]
									}

									console.log(dataToDecrypt);

									let dataToDecryptProcessed = [];

									_.each(dataToDecrypt, function (_dataToDecrypt)
									{
										if (_.isString(_dataToDecrypt))
										{
											dataToDecryptProcessed.push(
											{
												encrypted: _dataToDecrypt,
												data: entityosProtect.decrypt(
												{
													text: _dataToDecrypt,
													key: _key.key,
													iv: _key.iv
												}).textDecrypted
											})
										}
										else
										{
											_dataToDecrypt.data = entityosProtect.decrypt(
											{
												text: _dataToDecrypt.encrypted,
												key: _key.key,
												iv: _key.iv
											}).textDecrypted;

											dataToDecryptProcessed.push(_dataToDecrypt);
										}
									});
							
									if (_key.id == undefined)
									{
										_key.id = _.truncate(_key.keyhash, {length: 6});
									}

									var responseData =
									{
										"encrypted": dataToDecryptProcessed,
										"keyhash": _key.keyHash,
										"keyid": _key.id
									}

									entityos.invoke('util-end',
									{
										method: 'storage-protect-data-decrypt',
										status: 'OK',
										data: responseData
									},
									'200');
								}
							}
						}
					}
				}
			});

			// !!!! APP STARTS HERE; Initialise the app; app-init invokes app-start if authentication OK
			entityos.invoke('app-init');
		}	
   });

  	return promise
}