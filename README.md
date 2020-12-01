# Hapi Auth Dynamic JWT
[![Version][npm-image]][npm-url] ![Downloads][downloads-image] [![Build Status][status-image]][status-url] [![Open Issues][issues-image]][issues-url] [![Dependency Status][daviddm-image]][daviddm-url] ![License][license-image]

> Hapi plugin to authenticate and issue JSON Web Tokens based on rotating secrets

## Deprecated

**Please note that this code is no longer used by the screwdriver.cd team and has not been maintained in a while. You are welcome to use and/or contribute to it at your own risk.**

## Why

This plugin was written to solve two scenarios:

1. An attacker gains access to a copy of our private signing key.  We need to rotate the credential as fast as possible as well as update all downstream services to get our new key.  This plugin allows the downstream services to dynamically load the active keys.

2. We rotate our secrets on a regular basis (good practice).  When we do, existing JWTs in-flight would be invalidated (bad user experience).  This plugin allows us to preload multiple time-limited signing keys so that secrets are periodically rotated and JWTs that are issued will be guaranteed to be valid for their lifespan.

## Features

 - [X] Validates against multiple keys (with expiration)
 - [X] Exposes function to create new JWT based on TTL
 - [X] Exposes list of keys, expiration, and type
 - [X] Loads keys from remote server
 - [X] Reloads remote keys if key id not found
 - [X] Customizable timeout
 - [X] Customize issuer name
 - [X] Uses semaphore to prevent concurrent requests

## Usage

```bash
npm install --save hapi-auth-dynamic-jwt
```

### Configuration

There are two different modes to be in: server and remote.  Server-mode means it will host the private keys and can issue JWTs.  Remote-mode means it will validate JWTs against the public keys published from a server.

When providing keys for server-mode, these are the fields required:

 - `private`: Private key to sign JWTs
 - `public`: Public key to verify JWTs signed with the private key
 - `algorithm`: The key's algorithm, one of the ones on https://www.npmjs.com/package/jwa
 - `expires`: Unix timestamp it should expire at

### Example Auth Server

```js
const Hapi = require('hapi');
const server = new Hapi.Server();

server.connection({ port: 12345 });
server.register(require('hapi-auth-dynamic-jwt'))
.then(() => {
    server.auth.strategy('default', 'dynamic-jwt', {
        keys: [
            {
                private: 'FAKE_PRIVATE_KEY1',
                public: 'FAKE_PUBLIC_KEY2',
                algorithm: 'es512',
                expires: 1509480014
            },
            {
                private: 'FAKE_PRIVATE_KEY2',
                public: 'FAKE_PUBLIC_KEY2',
                algorithm: 'es512',
                expires: 1514209030
            }
        ],
        maxAge: '1h'
    });
    server.route({
        method: 'GET',
        path: '/protected-route',
        config: {
            auth: 'default',
            handler: (request, reply) => reply(request.auth.credentials)
        }
    });
    server.route({
        method: 'GET',
        path: '/keys',
        config: {
            handler: (request, reply) =>
                reply(server.plugins['hapi-auth-dynamic-jwt'].availableKeys())
        }
    });
    server.route({
        method: 'GET',
        path: '/new-jwt',
        config: {
            handler: (request, reply) =>
                reply(server.plugins['hapi-auth-dynamic-jwt'].createJWT({
                    subject: 'Bean',
                    payload: {
                        entity: {
                            fullname: 'Mr. Bean',
                            address: '12 Arbor Road, London'
                        },
                        scope: [
                            'admin'
                        ]
                    },
                    time: '5m'
                }))
        }
    });
});
```

### Example Auth Remote

```js
const Hapi = require('hapi');
const server = new Hapi.Server();

server.connection({ port: 12345 });
server.register({
    register: require('hapi-auth-dynamic-jwt'),
    options: {
        remoteUri: 'https://example.com/keys',
        timeout: 1
    }
}).then(() => {
    server.auth.strategy('default', 'dynamic-jwt');
    server.route({
        method: 'GET',
        path: '/protected-route',
        config: {
            auth: 'default',
            handler: (request, reply) => reply(request.auth.credentials)
        }
    });
});
```

## Testing

```bash
npm test
```

## License

Code licensed under the BSD 3-Clause license. See LICENSE file for terms.

[npm-image]: https://img.shields.io/npm/v/hapi-auth-dynamic-jwt.svg
[npm-url]: https://npmjs.org/package/hapi-auth-dynamic-jwt
[downloads-image]: https://img.shields.io/npm/dt/hapi-auth-dynamic-jwt.svg
[license-image]: https://img.shields.io/npm/l/hapi-auth-dynamic-jwt.svg
[issues-image]: https://img.shields.io/github/issues/screwdriver-cd/hapi-auth-dynamic-jwt.svg
[issues-url]: https://github.com/screwdriver-cd/hapi-auth-dynamic-jwt/issues
[status-image]: https://cd.screwdriver.cd/pipelines/360/badge
[status-url]: https://cd.screwdriver.cd/pipelines/360
[daviddm-image]: https://david-dm.org/screwdriver-cd/hapi-auth-dynamic-jwt.svg?theme=shields.io
[daviddm-url]: https://david-dm.org/screwdriver-cd/hapi-auth-dynamic-jwt
