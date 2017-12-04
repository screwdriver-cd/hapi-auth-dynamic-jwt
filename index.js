'use strict';

// @NOTE this module is styled based on http://hapijs.com/styleguide

const Boom = require('boom');
const Joi = require('joi');
const Jwt = require('jsonwebtoken');
const ms = require('ms');
const os = require('os');
const guid = require('aguid');
const request = require('request');
const semaphore = require('semaphore');
const pkg = require('./package.json');
const internals = {};

internals.REGEX_BEARER = /Bearer\s+(.+)$/i;
internals.SCHEMA_KEY = Joi.object({
    private: Joi.string()
        .required()
        .label('Private Key'),
    public: Joi.string()
        .required()
        .label('Public Key'),
    algorithm: Joi.string()
        .required()
        .label('Algorithm from https://www.npmjs.com/package/jwa'),
    expires: Joi.number()
        .integer().positive()
        .required()
        .label('UNIX Timestamp for key expiration')
});

internals.SCHEMA_LOCAL_KEYS = Joi.array()
    .min(1).items(internals.SCHEMA_KEY)
    .required()
    .label('List of private keys');
internals.SCHEMA_AGE = Joi.string()
    .default('12h')
    .optional()
    .label('Maximum JWT age');
internals.SCHEMA_ISSUER = Joi.string()
    .default(os.hostname())
    .optional()
    .label('Host that issues the JWT');
internals.SCHEMA_LOCAL_CONFIG = Joi.object({
    keys: internals.SCHEMA_LOCAL_KEYS,
    maxAge: internals.SCHEMA_AGE,
    issuer: internals.SCHEMA_ISSUER
}).required().label('Source-of-Truth Config');

internals.SCHEMA_REMOTE_URI = Joi.string()
    .uri()
    .required()
    .label('Remote URI for public keys');
internals.SCHEMA_TIMEOUT = Joi.number()
    .integer().positive()
    .default('5')
    .optional()
    .label('Timeout loading remote keys');
internals.SCHEMA_REMOTE_CONFIG = Joi.object({
    remoteUri: internals.SCHEMA_REMOTE_URI,
    timeout: internals.SCHEMA_TIMEOUT
}).required().label('Remote Config');

internals.SCHEMA_KEYS = Joi.alternatives(
    internals.SCHEMA_LOCAL_CONFIG,
    internals.SCHEMA_REMOTE_CONFIG
).required().label('List of private keys or Remote URI for public keys');

internals.SCHEMA_CREATE = Joi.object({
    subject: Joi.string()
        .required()
        .label('Subject of the JWT'),
    payload: Joi.object()
        .required()
        .label('Describing attributes about the subject'),
    scope: Joi.array()
        .default([])
        .label('List of permissions applied to this JWT'),
    time: Joi.string()
        .required()
        .label('Life of JWT')
}).required();

/**
 * Creates a Source-of-Truth auth services
 * @method loadLocal
 * @param  {Object}  authConfig         Input for setting up a local version
 * @param  {Array}   authConfig.keys    List of public/private keys
 * @param  {String}  authConfig.maxAge  Maximum age of JWTs
 * @param  {String}  authConfig.issuer  Name of issuing server
 * @return {Object}                     API to expose and getKey function
 */
internals.loadLocal = (authConfig) => {
    const keys = {};

    authConfig.keys.forEach((key) => {
        keys[guid(key.public)] = key;
    });

    const expireIds = Object.keys(keys).sort((keyA, keyB) =>
        keys[keyA].expires - keys[keyB].expires
    );

    return {
        /**
        * Load the key data
        * @method getKey
        * @param  {String}   keyId Key you are looking for
        * @param  {Function} next  Function to call when done (error, key)
        */
        getKey: (keyId, next) => {
            if (keys[keyId]) {
                return next(null, keys[keyId]);
            }

            return next(new Error('Specified Key Id not found'));
        },

        /**
         * Exposed API for the auth plugin
         * @type {Object}
         */
        api: {
            /**
             * Create new JWT based on the available keys
             * @method createJWT
             * @param  {Object}  jwtConfig
             * @param  {String}  jwtConfig.subject Thing that this represents
             * @param  {Object}  jwtConfig.payload Attributes about the subject
             * @param  {Array}   jwtConfig.scope   List of privileges
             * @param  {String}  jwtConfig.time    How long the credential will last
             * @return {String}                    Signed JSON Web Token
             */
            createJWT: (jwtConfig) => {
                const parsedConfig = Joi.attempt(jwtConfig, internals.SCHEMA_CREATE,
                    'Invalid JWT options');

                if (ms(parsedConfig.time) > ms(authConfig.maxAge)) {
                    throw new Error('Request exceeds max JWT age');
                }

                // Find the first key that expires AFTER the requested length of the key
                const signingKeyId = Object.keys(keys).find(keyId =>
                    (ms(parsedConfig.time) + Date.now()) / 1000 < keys[keyId].expires
                );
                const signingKey = keys[signingKeyId];

                if (!signingKey) {
                    throw new Error('No valid key exists to support this time range');
                }

                // Ensure that scope is included in the payload
                const payload = jwtConfig.payload;

                payload.scope = parsedConfig.scope;

                return Jwt.sign(payload, signingKey.private, {
                    algorithm: signingKey.algorithm,
                    expiresIn: parsedConfig.time,
                    notBefore: 0,
                    issuer: authConfig.issuer,
                    jwtid: guid(),
                    keyid: signingKeyId,
                    subject: parsedConfig.subject
                });
            },

            /**
             * List only the active keys (no larger than maxAge)
             * @method availableKeys
             * @return {Object}      KeyId => public, expire, algorithm
             */
            availableKeys: () => {
                const nowDate = Date.now() / 1000;
                const maxDate = nowDate + (ms(authConfig.maxAge) / 1000);
                const output = {};

                expireIds.some((keyId) => {
                    if (nowDate > keys[keyId].expires) {
                        return false;
                    }

                    if (maxDate > keys[keyId].expires) {
                        return false;
                    }

                    output[keyId] = {
                        public: keys[keyId].public,
                        algorithm: keys[keyId].algorithm,
                        expires: keys[keyId].expires
                    };

                    return true;
                });

                return output;
            }
        }
    };
};

/**
 * Creates a Remote auth service
 * @method loadRemote
 * @param  {Object}  authConfig           Input for setting up a remote version
 * @param  {String}  authConfig.remoteUri URI of remote server
 * @param  {String}  authConfig.timeout   How long to wait for API response
 * @param  {String}  authConfig.issuer    Name of issuing server
 * @return {Object}                       Contains keys, apis, etc.
 */
internals.loadRemote = (authConfig) => {
    const mutex = semaphore(1);
    let keys = {};

    return {
        /**
         * Load the key data (from the remote server if needed)
         * @method getKey
         * @param  {String}   keyId Key you are looking for
         * @param  {Function} next  Function to call when done (error, key)
         */
        getKey: (keyId, next) => {
            const nextSem = (err, result) => {
                mutex.leave();
                next(err, result);
            };

            // Prevent multiple calls to the remote URI
            mutex.take(() => {
                if (keys[keyId]) {
                    return nextSem(null, keys[keyId]);
                }

                return request({
                    url: authConfig.remoteUri,
                    headers: {
                        'user-agent': `${pkg.name}@${pkg.version}`,
                        'hapi-auth-requested-key': keyId
                    },
                    json: true,
                    timeout: authConfig.timeout
                }, (reqError, response, body) => {
                    if (reqError || response.statusCode !== 200) {
                        const prevError = reqError ||
                            new Error(`Status Code: ${response.statusCode}`);

                        return nextSem(prevError);
                    }

                    keys = {};
                    body.forEach((key) => {
                        keys[guid(key.public)] = key;
                    });

                    if (keys[keyId]) {
                        return nextSem(null, keys[keyId]);
                    }

                    return nextSem(new Error('Specified Key Id not found'));
                });
            });
        }
    };
};

/**
 * Configures the authentication plugin of Hapi
 * @method implementation
 * @param  {HapiServer} server           HapiServer we are attaching the auth service to
 * @param  {Object}     config           Plugin configuration
 * @param  {Array}      config.keys      List of private keys to sign JWTs with
 * @param  {String}     config.maxAge    Maximum age for signing JWTs
 * @param  {String}     config.remoteUri URI of remote keys
 * @param  {String}     config.timeout   How long to wait for API response
 * @param  {String}     config.issuer    Name of issuing server
 * @return {Object}                      Contains an authenticate function to parse each request
 */
internals.implementation = (server, config) => {
    const authConfig = Joi.attempt(config, internals.SCHEMA_KEYS,
        'Invalid config for hapi-auth-dynamic-jwt plugin');
    let authObject = {};

    // Local mode
    if (typeof authConfig.keys === 'object') {
        authObject = internals.loadLocal(authConfig);
    } else {
        authObject = internals.loadRemote(authConfig);
    }

    return {
        api: authObject.api,

        /**
         * Replies with the parsed credentials or an error based on the input from request
         * @method authenticate
         * @param  {HapiRequest}   req     Route handler request object
         * @param  {HapiReply}     reply   Reply interface
         * @return {Function}              Result of Reply interface
         */
        authenticate: (req, reply) => {
            const parsedHeader = internals.REGEX_BEARER.exec(req.headers.authorization);

            /**
             * Reply with a unauthorized error message
             * @method replyError
             * @param  {String}    message Error message
             * @return {Promise}
             */
            const replyError = message =>
                reply(Boom.unauthorized(null, 'Bearer', {
                    error: message
                }));

            // Ensure we have the header
            if (!parsedHeader) {
                return replyError('Missing JWT');
            }

            const token = parsedHeader[1];
            const parsedToken = Jwt.decode(token, {
                complete: true
            });

            // Check if it's valid JWT
            if (!parsedToken) {
                return replyError('Invalid JWT format');
            }

            const { payload, header } = parsedToken;

            // Ensure we have the key requested
            return authObject.getKey(header.kid, (keyError, signingKey) => {
                if (keyError) {
                    server.log(['auth', 'error', req.name], keyError.toString());

                    return replyError('Unknown JWT public key ID');
                }

                // Check if the key is expired
                if (signingKey.expires < Date.now() / 1000) {
                    return replyError('JWT key has expired');
                }

                // Verify the signature
                try {
                    Jwt.verify(token, signingKey.public, {
                        algorithms: [signingKey.algorithm]
                    });
                } catch (jwtError) {
                    return replyError(`Invalid JWT signature: ${jwtError.toString()}`);
                }

                return reply.continue({
                    credentials: payload,
                    artifacts: { token }
                });
            });
        }
    };
};

/**
 * Registers the auth plugin and required routes
 * @see http://hapijs.com/api#serverplugins
 * @method register
 * @param  {HapiServer}  server  Hapi Server we are attaching this plugin to
 * @param  {Object}      options Configuration for the plugin
 * @param  {Function}    next    Callback once registration succeeds
 */
exports.register = (server, options, next) => {
    // Configure authentication
    server.auth.scheme('dynamic-jwt', internals.implementation);

    return process.nextTick(next);
};

/**
 * Exposes the package name and version number to Hapi
 * @type {Object}
 */
exports.register.attributes = { pkg };
