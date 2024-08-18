/*
	LEARN; Storaging files on storage services.
	e.g iagon.com

	Also see learn.js for more example code using the entityos node module.

	References:

	# https://buildingoncardano.dev
	# https://docs.iagon.com/docs/mainnet-guide/api/
	# https://docs.api.iagon.com/#987c958c-f6bd-4b9c-98f0-e3b8e3a2b1f9

	To run it on your local computer your need to install:

	https://www.npmjs.com/package/lambda-local:

	And then run as:
	lambda-local -l learn-storage.js -t 9000 -e learn-event-storage-usage.json
	lambda-local -l learn-storage.js -t 9000 -e learn-event-storage-file-system.json

*/

exports.handler = function (event, context, callback)
{
	var entityos = require('entityos')
	var _ = require('lodash')
	var moment = require('moment');

	/*
		[LEARN #1]
		Store the event data and callback for use by controllers later.
	*/

	entityos.set(
	{
		scope: '_event',
		value: event
	});

	entityos.set(
	{
		scope: '_callback',
		value: callback
	});

	entityos.init(main);

	function main(err, data)
	{
		/*
			[LEARN #2]
			This example shows how to get file storage from iagon API.
		*/

		entityos.add(
		{
			name: 'learn-storage-init',
			code: function ()
			{
				console.log('Using entityos module version ' + entityos.VERSION);

				var settings = entityos.get({ scope: '_settings' });
				console.log(settings, 'SETTINGS');

				if (event.method == undefined)
				{
					event.method = 'learn-storage-usage';
				}

				if (event.provider != undefined)
				{
					settings.storage.provider = event.provider;
				}

				if (settings.storage.provider.hostname == undefined)
				{
					entityos.invoke('util-end', 'No hostname [settings.json|storage.provider]');
				}
				else
				{
					entityos.invoke(event.method);
				}
			}
		});

		//-- GET STORAGE USAGE

		entityos.add(
		[
			{
				name: 'learn-storage-usage',
				code: function ()
				{
					var settings = entityos.get({ scope: '_settings' });

					if (settings.storage.provider.hostname == undefined)
					{
						entityos.invoke('util-end', 'No hostname [settings.json|storage.provider]');
					}
					else
					{
						entityos._util.send(
						{
							headers: { 'x-api-key': settings.storage.provider.apikey },
							hostname: settings.storage.provider.hostname,
							path: '/api/v2/storage/consumed',
							method: 'GET'
						},
						'learn-storage-usage-process');
					}
				}
			},		
			{
				name: 'learn-storage-usage-process',
				code: function (options, response)
				{
					console.log('>>learn-storage-usage-process')

					var event = entityos.get({ scope: '_event' });
					var settings = entityos.get({ scope: '_settings' });

					entityos._util.testing.data(response.data, 'learn-storage-usage-process')

					event.usage = { totalNativeFileSizeInKB: response.data.data.totalNativeFileSizeInKB }
					event._apikey = _.truncate(settings.storage.provider.apikey, { length: 20 });

					entityos.invoke('util-end', event);
				}
			}
		]);

		//-- LIST DIRECTORIES / FILES

		entityos.add(
		[
			{
				name: 'learn-storage-file-system',
				code: function ()
				{
					var settings = entityos.get({ scope: '_settings' });
					var event = entityos.get({ scope: '_event' });

					if (event.action != undefined)
					{
						//get-root-directory is default, so do nothing in this case
						//else add say &"parent_directory_id=
					}

					entityos._util.send(
					{
						headers: { 'x-api-key': settings.storage.provider.apikey },
						hostname: settings.storage.provider.hostname,
						path: '/api/v2/storage/directory?visibility=public&listingType=index',
						method: 'GET'
					},
					'learn-storage-file-system-process');
				}
			},		
			{
				name: 'learn-storage-file-system-process',
				code: function (options, response)
				{
					var event = entityos.get({ scope: '_event' });
					var settings = entityos.get({ scope: '_settings' });

					entityos._util.testing.data(response, 'learn-storage-file-system-process');

					var event = entityos.get({ scope: '_event' });

					event.filesystem = {}

					if (response.data.data.directories.length != 0)
					{
						event.filesystem.info = _.first(response.data.data.directories);
					}

					if (event.action == 'get-root-directory' && event.filesystem.info != undefined)
					{
						event.filesystem.root = event.filesystem.info._id;
					}
					
					event._apikey = _.truncate(settings.storage.provider.apikey, { length: 20 });

					entityos.invoke('util-end', event);
				}
			}
		]);

		entityos.add(
		{
			name: 'util-end',
			code: function (data, error)
			{
				var callback = entityos.get(
				{
					scope: '_callback'
				});

				if (error == undefined) { error = null }

				if (callback != undefined)
				{
					callback(error, data);
				}
			}
		});

		//STARTS HERE!
		entityos.invoke('learn-storage-init');
	}
}