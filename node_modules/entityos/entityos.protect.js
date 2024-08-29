var _ = require('lodash')
var moment = require('moment');
var entityos = require('entityos/entityos.js');

module.exports = 
{
	VERSION: '1.0.4',

	data: {},

	hash: function (param)
    {
        const { createHash, publicDecrypt, privateDecrypt } = require('crypto');

        if (param.hashMethod == undefined)
        {
            param.hashMethod = 'sha256';
        }

		let output = _.get(param, 'output');
        if (output == undefined)
        {
           output = 'base64';
        }

		let base58 = false;
		if (output == 'base58')
		{
			output = 'hex';
			base58 = true;
		}

        param.textHashed = createHash(param.hashMethod).update(param.text).digest(param.output);

		if (base58)
		{
			param.textHashed = module.exports.convert(
			{
				input: 'hex',
				output: 'base58',
				text: param.textHashed
			}).textConverted;
		}

        return param;     
    },

	convert: function (param)
    {
		input = _.get(param, 'input', 'hex').toLowerCase();
		output = _.get(param, 'output', 'base58').toLowerCase();
		text = _.get(param, 'text');

		if (output == 'base58' && text != undefined)
		{
			const bs58 = require('bs58');
			const buffer = Buffer.from(text, 'hex');
 			textConverted = bs58.encode(buffer);
		}

		param.textConverted = textConverted;

		return param;
	},

    hashWithKey: function (param)
    {
        const { createHmac } = require('crypto');

        if (param.hashMethod == undefined)
        {
            param.hashMethod = 'sha256';
        }

        if (param.output == undefined)
        {
            param.output = 'base64';
        }

        param.textHashedWithKey = createHmac(param.hashMethod, param.keyPrivate).update(param.text).digest(param.output);

        return param;  
    },

    hashWithSalt: function (param)
    {
        const { scryptSync, randomBytes, timingSafeEqual } = require('crypto');

        if (param.output == undefined)
        {
            param.output = 'hex' // 'base64'
        }

        param.salt = randomBytes(16).toString('hex');
        param.textHashedWithSalt = scryptSync(param.text,  param.salt, 64).toString(param.output);

       return param;     
    },

    createKeys: function (param)
    {
        const { generateKeyPairSync } = require('crypto');

        if (param.keyMethod == undefined)
        {
            param.keyMethod = 'rsa'
        }

        if (param.keyLength == undefined)
        {
            param.keyLength = 2048
        }

        if (param.output == undefined)
        {
            param.output = 'base64'
        }

        param.keyPublicType = 'spki' // recommended to be 'spki' by the Node.js docs
        param.keyPrivateType = 'pkcs8' // recommended to be 'spki' by the Node.js docs

        const { privateKey, publicKey } = generateKeyPairSync(param.keyMethod,
        {
            modulusLength: param.keyLength, // the length of your key in bits
            publicKeyEncoding:
            {
                type: param.keyPublicType,
                format: 'pem',
            },
            privateKeyEncoding:
            {
                type: param.keyPrivateType,
                format: 'pem',
                cipher: param.keyCipher // 'aes-256-cbc',
                // passphrase: param.keyCipherSecret // 'top secret'
            },
        });
          
        param.keyPrivate = privateKey;
        param.keyPublic = publicKey;

        return param;     
    },

    encrypt: function (param)
    {
        const { createCipheriv, randomBytes } = require('crypto');

        if (param.key == undefined)
        {
            param.keyPrivate = randomBytes(32);
			param.key =  param.keyPrivate.toString('hex');
        }

        if (param.iv == undefined)
        {
            param.initialisationVector = randomBytes(16);
			param.iv =  param.initialisationVector.toString('hex');
        }
    
        if (param.encryptionMethod == undefined)
        {
            param.encryptionMethod = 'aes256'
        }

		param._keyPrivate = new Buffer.from(param.key, 'hex');
        param._initialisationVector = new Buffer.from(param.iv, 'hex');

        const cipher = createCipheriv(param.encryptionMethod, param._keyPrivate, param._initialisationVector);

        if (param.output == undefined)
        {
            param.output = 'hex' // 'base64'
        }

        param.textEncrypted = cipher.update(param.text, 'utf8', param.output) + cipher.final(param.output);

        return param;     
    },

    decrypt: function (param)
    {
        const { createDecipheriv, randomBytes } = require('crypto');

		if (param.key == undefined)
        {
			param.key =  param.keyPrivate
        }

		if (param.iv == undefined)
        {
			param.key =  param.initialisationVector
        }

        param._keyPrivate = new Buffer.from(param.key, 'hex');
        param._initialisationVector = new Buffer.from(param.iv, 'hex');
        
        if (param.encryptionMethod == undefined)
        {
            param.encryptionMethod = 'aes256'
        }

        const decipher = createDecipheriv(param.encryptionMethod, param._keyPrivate, param._initialisationVector);

        if (param.output == undefined)
        {
            param.output = 'hex' // 'base64'
        }

        param.textDecrypted = decipher.update(param.text, param.output, 'utf8') + decipher.final('utf8');

        return param;     
    },
	
    sign: function (param)
    {
        const { createSign, createVerify } = require('crypto');
        const { generateKeyPairSync } = require('crypto');

        if (param.keyLength == undefined)
        {
            param.keyLength = 2048
        }

        param.keyPublicType = 'spki' // recommended to be 'spki' by the Node.js docs
        param.keyPrivateType = 'pkcs8' // recommended to be 'spki' by the Node.js docs

        if (param.privateKey == undefined || param.publicKey == undefined)
        {
            const { privateKey, publicKey } = generateKeyPairSync('rsa',
            {
                modulusLength: param.keyLength,
                publicKeyEncoding:
                {
                    type: param.keyPublicType,
                    format: 'pem',
                },
                privateKeyEncoding:
                {
                    type: param.keyPrivateType,
                    format: 'pem'
                },
            });

            param.privateKey = privateKey;
            param.publicKey = publicKey;
        }

        const signer = createSign('rsa-sha256');
        signer.update(param.text);
        param.textSignature = signer.sign(privateKey, 'hex');

        return param;     
    },

    encryptUsingAlgorithm: function (param)
    {
        const { publicEncrypt, privateEncrypt } = require('crypto');
        const { generateKeyPairSync } = require('crypto');

        if (param.privateKey == undefined && param.publicKey == undefined)
        {
            param.keyPublicType = 'spki' // recommended to be 'spki' by the Node.js docs
            param.keyPrivateType = 'pkcs8' // recommended to be 'spki' by the Node.js docs

            if (param.keyLength == undefined)
            {
                param.keyLength = 2048
            }

            const { privateKey, publicKey } = generateKeyPairSync('rsa',
            {
                modulusLength: param.keyLength,
                publicKeyEncoding:
                {
                    type: param.keyPublicType,
                    format: 'pem',
                },
                privateKeyEncoding:
                {
                    type: param.keyPrivateType,
                    format: 'pem'
                },
            });

            param._keyPrivate = privateKey;
            param._keyPublic = publicKey;
        }
        else
        {
            if (param.keyPrivate != undefined)
            {
                param._keyPrivate = new Buffer.from(param.keyPrivate, 'hex');
            }

            if (param.keyPublic != undefined)
            {
                param._keyPublic = new Buffer.from(param.keyPublic, 'hex');
            }
        }

        if (param._keyPrivate != undefined)
        {
            param.textEncrypted = privateEncrypt(
                param._keyPrivate,
                Buffer.from(param.text)
            ).toString('hex');

            param.encryptedUsingPrivateKey = true;
        }
        else if (param._keyPublic != undefined)
        {
            param.textEncrypted = publicEncrypt(
                param._keyPublic,
                Buffer.from(param.text)
            ).toString('hex');

            param.encryptedUsingPublicKey = true;
        }

        return param;     
    },

    decryptUsingAlgorithm: function (param)
    {
        const { publicDecrypt, privateDecrypt } = require('crypto');

        if (param.keyPublic != undefined)
        {
            param._keyPublic = param.keyPublic;
        }

        if (param.keyPrivate != undefined)
        {
            param._keyPrivate = param.keyPrivate;
        }

        if (param._keyPublic != undefined)
        {               
            param.textDecrypted = publicDecrypt(
                param._keyPublic,
                Buffer.from(param.text, 'hex')
            ).toString('utf-8');

            param.decryptedUsingPublicKey = true;
        }
        else if (param._keyPrivate != undefined)
        {
            param.textDecrypted = privateDecrypt(
                param._keyPrivate,
                Buffer.from(param.text, 'hex')
            ).toString('utf-8');

            param.decryptedUsingPrivateKey = true;
        }
        
        return param;     
    }
}