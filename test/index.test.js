'use strict';

const hapi = require('hapi');
const chai = require('chai');
const mockery = require('mockery');
const sinon = require('sinon');
const ms = require('ms');
const nock = require('nock');
const assert = chai.assert;

chai.use(require('chai-as-promised'));

sinon.assert.expose(chai.assert, { prefix: '' });

/**
 * Generates a random key to provide to the input
 * @method randomKey
 * @param  {String}  expiresIn     Time before expires
 * @param  {Boolean} [isNegative]  Make the time negative
 * @param  {Boolean} [skipPrivate] Ignore private keys
 * @return {Object}                Key format needed by the plugin
 */
function randomKey(expiresIn, isNegative, skipPrivate) {
    let expires = ms(expiresIn || '5m');

    if (isNegative) {
        expires *= -1;
    }

    const key = {
        private: `FAKE_PRIVATE_KEY1${expires}`,
        public: `FAKE_PUBLIC_KEY1${expires}`,
        algorithm: 'es512',
        expires: Math.floor((Date.now() + expires) / 1000)
    };

    if (skipPrivate) {
        delete key.private;
    }

    return key;
}

describe('hapi-auth-dynamic-jwt test', () => {
    let plugin;
    let server;
    let jwtMock;

    before(() => {
        mockery.enable({
            useCleanCache: true,
            warnOnUnregistered: false
        });
    });

    beforeEach(() => {
        jwtMock = {
            verify: sinon.stub(),
            decode: sinon.stub(),
            sign: sinon.stub()
        };
        mockery.registerMock('jsonwebtoken', jwtMock);

        nock.disableNetConnect();

        /* eslint-disable global-require */
        plugin = require('../index');
        /* eslint-enable global-require */
        server = new hapi.Server();
        server.connection({
            port: 1234
        });
    });

    afterEach(() => {
        server = null;
        mockery.deregisterAll();
        mockery.resetCache();
        nock.cleanAll();
    });

    after(() => {
        mockery.disable();
    });

    describe('registration', () => {
        it('registers the plugin', () =>
            server.register(plugin).then(() =>
                server.auth.strategy('default', 'dynamic-jwt', false, {
                    keys: [randomKey()]
                })
            ).then(() => {
                assert.property(server.registrations, 'hapi-auth-dynamic-jwt');
            })
        );

        it('requires keys', () =>
            server.register(plugin).then(() =>
                server.auth.strategy('default', 'dynamic-jwt', false)
            ).then(() =>
                assert.fail()
            ).catch(err => assert.match(err.toString(),
                /"Source-of-Truth Config" must be an object/))
        );

        it('requires keys in the right format', () =>
            server.register(plugin).then(() =>
                server.auth.strategy('default', 'dynamic-jwt', false, {
                    keys: [{}]
                })
            ).then(() =>
                assert.fail()
            ).catch(err => assert.match(err.toString(), /"Private Key" is required/))
        );
    });

    describe('validation', () => {
        beforeEach(() => server.register(plugin)
            .then(() => server.auth.strategy('default', 'dynamic-jwt', false, {
                keys: [randomKey(), randomKey('5m', true)]
            }))
        );

        it('requires a JWT to be passed', () => {
            server.route({
                method: 'GET',
                path: '/protected-route',
                config: {
                    auth: 'default',
                    handler: (request, reply) => reply({})
                }
            });

            return server.inject({
                url: '/protected-route'
            }).then((reply) => {
                assert.equal(reply.statusCode, 401);
                assert.property(reply.headers, 'www-authenticate');
                assert.match(reply.headers['www-authenticate'], /Bearer/);
                assert.match(reply.headers['www-authenticate'], /Missing JWT/);
            });
        });

        it('requires a valid JWT to be passed', () => {
            server.route({
                method: 'GET',
                path: '/protected-route',
                config: {
                    auth: 'default',
                    handler: (request, reply) => reply({})
                }
            });
            jwtMock.decode.returns(null);

            return server.inject({
                url: '/protected-route',
                headers: {
                    authorization: 'Bearer FOOBARBAZ'
                }
            }).then((reply) => {
                assert.equal(reply.statusCode, 401);
                assert.property(reply.headers, 'www-authenticate');
                assert.match(reply.headers['www-authenticate'], /Bearer/);
                assert.match(reply.headers['www-authenticate'], /Invalid JWT format/);
            });
        });

        it('requires a matching key ID to be passed', () => {
            server.route({
                method: 'GET',
                path: '/protected-route',
                config: {
                    auth: 'default',
                    handler: (request, reply) => reply({})
                }
            });
            jwtMock.decode.returns({
                header: {
                    kid: 'f3907a3b-4d2e-426b-a9d5-111b35752d58'
                },
                payload: {}
            });

            return server.inject({
                url: '/protected-route',
                headers: {
                    authorization: 'Bearer FOOBARBAZ'
                }
            }).then((reply) => {
                assert.equal(reply.statusCode, 401);
                assert.property(reply.headers, 'www-authenticate');
                assert.match(reply.headers['www-authenticate'], /Bearer/);
                assert.match(reply.headers['www-authenticate'], /Unknown JWT public key ID/);
            });
        });

        it('fails if key is expired', () => {
            server.route({
                method: 'GET',
                path: '/protected-route',
                config: {
                    auth: 'default',
                    handler: (request, reply) => reply({})
                }
            });
            jwtMock.decode.returns({
                header: {
                    kid: 'dbe0be9b-4cb3-4bcc-8e27-16f8f52313e4'
                },
                payload: {}
            });

            return server.inject({
                url: '/protected-route',
                headers: {
                    authorization: 'Bearer FOOBARBAZ'
                }
            }).then((reply) => {
                assert.equal(reply.statusCode, 401);
                assert.property(reply.headers, 'www-authenticate');
                assert.match(reply.headers['www-authenticate'], /Bearer/);
                assert.match(reply.headers['www-authenticate'], /JWT key has expired/);
            });
        });

        it('requires a valid signed JWT to be passed', () => {
            server.route({
                method: 'GET',
                path: '/protected-route',
                config: {
                    auth: 'default',
                    handler: (request, reply) => reply({})
                }
            });
            jwtMock.decode.returns({
                header: {
                    kid: 'f8b86ef5-6f71-40bd-8add-529b4201834c'
                },
                payload: {}
            });
            jwtMock.verify.throws(new Error('Invalid JWT'));

            return server.inject({
                url: '/protected-route',
                headers: {
                    authorization: 'Bearer FOOBARBAZ'
                }
            }).then((reply) => {
                assert.equal(reply.statusCode, 401);
                assert.property(reply.headers, 'www-authenticate');
                assert.match(reply.headers['www-authenticate'], /Bearer/);
                assert.match(reply.headers['www-authenticate'], /Invalid JWT signature/);
            });
        });

        it('returns credentials if passed', () => {
            server.route({
                method: 'GET',
                path: '/protected-route',
                config: {
                    auth: 'default',
                    handler: (request, reply) => reply({
                        credentials: request.auth.credentials,
                        artifacts: request.auth.artifacts
                    })
                }
            });
            jwtMock.decode.returns({
                header: {
                    kid: 'f8b86ef5-6f71-40bd-8add-529b4201834c'
                },
                payload: {
                    sub: 'sample user'
                }
            });
            jwtMock.verify.returns();

            return server.inject({
                url: '/protected-route',
                headers: {
                    authorization: 'Bearer FOOBARBAZ'
                }
            }).then((reply) => {
                assert.equal(reply.statusCode, 200);
                assert.property(reply.result, 'credentials');
                assert.property(reply.result.credentials, 'sub');
                assert.equal(reply.result.credentials.sub, 'sample user');
                assert.property(reply.result, 'artifacts');
                assert.property(reply.result.artifacts, 'token');
                assert.equal(reply.result.artifacts.token, 'FOOBARBAZ');
            });
        });
    });

    describe('create', () => {
        beforeEach(() => server.register(plugin)
            .then(() => server.auth.strategy('default', 'dynamic-jwt', false, {
                keys: [randomKey('5s'), randomKey('5m')],
                maxAge: '6h'
            }))
        );

        it('fails if invalid conf', () => {
            try {
                server.auth.api.default.createJWT({});
                assert.fail();
            } catch (error) {
                assert.match(error.toString(), /Invalid JWT options/);
            }
        });

        it('picks appropriate key based on expire', () => {
            jwtMock.sign.returns('aaaaaaaaaa.bbbbbbbbbbb.cccccccccccc');

            assert.equal(server.auth.api.default.createJWT({
                subject: 'foo',
                payload: { a: 'b' },
                time: '1s'
            }), 'aaaaaaaaaa.bbbbbbbbbbb.cccccccccccc');
            assert.calledWithMatch(jwtMock.sign,
                {
                    a: 'b'
                },
                'FAKE_PRIVATE_KEY15000',
                {
                    algorithm: 'es512',
                    expiresIn: '1s',
                    keyid: '0f2cadd8-69e0-42a9-8f46-b4722dcc722a',
                    notBefore: 0,
                    subject: 'foo'
                }
            );
        });

        it('fails if no valid keys available', () => {
            try {
                server.auth.api.default.createJWT({
                    subject: 'foo',
                    payload: { a: 'b' },
                    time: '5h'
                });
                assert.fail();
            } catch (error) {
                assert.match(error.toString(), /No valid key exists/);
            }
        });

        it('fails if outside max age', () => {
            try {
                server.auth.api.default.createJWT({
                    subject: 'foo',
                    payload: { a: 'b' },
                    time: '6d'
                });
                assert.fail();
            } catch (error) {
                assert.match(error.toString(), /Request exceeds max JWT age/);
            }
        });

        it('generates new credential', () => {
            jwtMock.sign.returns('aaaaaaaaaa.bbbbbbbbbbb.cccccccccccc');

            assert.equal(server.auth.api.default.createJWT({
                subject: 'foo',
                payload: { a: 'b' },
                time: '1m'
            }), 'aaaaaaaaaa.bbbbbbbbbbb.cccccccccccc');
            assert.calledWithMatch(jwtMock.sign,
                {
                    a: 'b'
                },
                'FAKE_PRIVATE_KEY1300000',
                {
                    algorithm: 'es512',
                    expiresIn: '1m',
                    keyid: 'f8b86ef5-6f71-40bd-8add-529b4201834c',
                    notBefore: 0,
                    subject: 'foo'
                }
            );
        });
    });

    describe('list', () => {
        const keys = [randomKey('5s', true), randomKey('45s'), randomKey('5m'), randomKey('10m')];

        beforeEach(() => server.register(plugin)
            .then(() => server.auth.strategy('default', 'dynamic-jwt', false, {
                maxAge: '1m',
                keys
            }))
        );

        it('lists just possibly active jwt keys', () => {
            assert.deepEqual(server.auth.api.default.availableKeys(), {
                'f8b86ef5-6f71-40bd-8add-529b4201834c': {
                    public: 'FAKE_PUBLIC_KEY1300000',
                    algorithm: 'es512',
                    expires: keys[2].expires
                }
            });
        });
    });

    describe('remote-keys', () => {
        it('throws error if unable to load', () => {
            nock('https://example.com')
                .get('/keys')
                .reply(404);

            return server.register(plugin).then(() => {
                server.auth.strategy('default', 'dynamic-jwt', false, {
                    remoteUri: 'https://example.com/keys'
                });
                server.route({
                    method: 'GET',
                    path: '/protected-route',
                    config: {
                        auth: 'default',
                        handler: (request, reply) => reply(request.auth.credentials)
                    }
                });
                jwtMock.decode.returns({
                    header: {
                        kid: 'f8b86ef5-6f71-40bd-8add-529b4201834c'
                    },
                    payload: {
                        sub: 'sample user'
                    }
                });
                jwtMock.verify.returns();

                return server.inject({
                    url: '/protected-route',
                    headers: {
                        authorization: 'Bearer FOOBARBAZ'
                    }
                }).then((reply) => {
                    assert.equal(reply.statusCode, 401);
                    assert.property(reply.headers, 'www-authenticate');
                    assert.match(reply.headers['www-authenticate'], /Bearer/);
                    assert.match(reply.headers['www-authenticate'], /Unknown JWT public key ID/);
                });
            });
        });

        it('throws error if bad response', () => {
            nock('https://example.com')
                .get('/keys')
                .replyWithError('Oh No');

            return server.register(plugin).then(() => {
                server.auth.strategy('default', 'dynamic-jwt', false, {
                    remoteUri: 'https://example.com/keys'
                });
                server.route({
                    method: 'GET',
                    path: '/protected-route',
                    config: {
                        auth: 'default',
                        handler: (request, reply) => reply(request.auth.credentials)
                    }
                });
                jwtMock.decode.returns({
                    header: {
                        kid: 'f8b86ef5-6f71-40bd-8add-529b4201834c'
                    },
                    payload: {
                        sub: 'sample user'
                    }
                });
                jwtMock.verify.returns();

                return server.inject({
                    url: '/protected-route',
                    headers: {
                        authorization: 'Bearer FOOBARBAZ'
                    }
                }).then((reply) => {
                    assert.equal(reply.statusCode, 401);
                    assert.property(reply.headers, 'www-authenticate');
                    assert.match(reply.headers['www-authenticate'], /Bearer/);
                    assert.match(reply.headers['www-authenticate'], /Unknown JWT public key ID/);
                });
            });
        });

        it('returns credentials if passed', () => {
            nock('https://example.com')
                .get('/keys')
                .reply(200, [
                    randomKey('5s', false, true),
                    randomKey('5m', false, true)
                ]);

            return server.register(plugin).then(() => {
                server.auth.strategy('default', 'dynamic-jwt', false, {
                    remoteUri: 'https://example.com/keys'
                });
                server.route({
                    method: 'GET',
                    path: '/protected-route',
                    config: {
                        auth: 'default',
                        handler: (request, reply) => reply(request.auth.credentials)
                    }
                });
                jwtMock.decode.returns({
                    header: {
                        kid: 'f8b86ef5-6f71-40bd-8add-529b4201834c'
                    },
                    payload: {
                        sub: 'sample user'
                    }
                });
                jwtMock.verify.returns();

                return server.inject({
                    url: '/protected-route',
                    headers: {
                        authorization: 'Bearer FOOBARBAZ'
                    }
                }).then((reply) => {
                    assert.equal(reply.statusCode, 200);
                    assert.property(reply.result, 'sub');
                    assert.equal(reply.result.sub, 'sample user');
                });
            });
        });

        it('returns cached key', () => {
            nock('https://example.com')
                .get('/keys')
                .reply(200, [
                    randomKey('5s', false, true),
                    randomKey('5m', false, true)
                ])
                .get('/keys')
                .reply(200, [
                    randomKey('10s', false, true),
                    randomKey('10m', false, true)
                ]);

            return server.register(plugin).then(() => {
                server.auth.strategy('default', 'dynamic-jwt', false, {
                    remoteUri: 'https://example.com/keys'
                });
                server.route({
                    method: 'GET',
                    path: '/protected-route',
                    config: {
                        auth: 'default',
                        handler: (request, reply) => reply(request.auth.credentials)
                    }
                });
                jwtMock.decode.returns({
                    header: {
                        kid: 'f8b86ef5-6f71-40bd-8add-529b4201834c'
                    },
                    payload: {
                        sub: 'sample user'
                    }
                });
                jwtMock.verify.returns();

                return server.inject({
                    url: '/protected-route',
                    headers: {
                        authorization: 'Bearer FOOBARBAZ'
                    }
                }).then((reply) => {
                    assert.equal(reply.statusCode, 200);
                    assert.property(reply.result, 'sub');
                    assert.equal(reply.result.sub, 'sample user');
                }).then(() => server.inject({
                    url: '/protected-route',
                    headers: {
                        authorization: 'Bearer FOOBARBAZ'
                    }
                })).then((reply) => {
                    assert.equal(reply.statusCode, 200);
                    assert.property(reply.result, 'sub');
                    assert.equal(reply.result.sub, 'sample user');
                });
            });
        });

        it('fails if key not found after reload', () => {
            nock('https://example.com')
                .get('/keys')
                .reply(200, [
                    randomKey('5s', false, true),
                    randomKey('5m', false, true)
                ])
                .get('/keys')
                .reply(200, [
                    randomKey('10s', false, true),
                    randomKey('10m', false, true)
                ]);

            return server.register(plugin).then(() => {
                server.auth.strategy('default', 'dynamic-jwt', false, {
                    remoteUri: 'https://example.com/keys'
                });
                server.route({
                    method: 'GET',
                    path: '/protected-route',
                    config: {
                        auth: 'default',
                        handler: (request, reply) => reply(request.auth.credentials)
                    }
                });
                jwtMock.decode.returns({
                    header: {
                        kid: '123c5121-185f-45b1-9bcb-e16c7c09517b'
                    },
                    payload: {
                        sub: 'sample user'
                    }
                });
                jwtMock.verify.returns();

                return server.inject({
                    url: '/protected-route',
                    headers: {
                        authorization: 'Bearer FOOBARBAZ'
                    }
                }).then((reply) => {
                    assert.equal(reply.statusCode, 401);
                    assert.property(reply.headers, 'www-authenticate');
                    assert.match(reply.headers['www-authenticate'], /Bearer/);
                    assert.match(reply.headers['www-authenticate'], /Unknown JWT public key ID/);
                }).then(() => server.inject({
                    url: '/protected-route',
                    headers: {
                        authorization: 'Bearer FOOBARBAZ'
                    }
                })).then((reply) => {
                    assert.equal(reply.statusCode, 401);
                    assert.property(reply.headers, 'www-authenticate');
                    assert.match(reply.headers['www-authenticate'], /Bearer/);
                    assert.match(reply.headers['www-authenticate'], /Unknown JWT public key ID/);
                });
            });
        });

        it('prevents duplicate calls', () => {
            nock('https://example.com')
                .get('/keys')
                .reply(200, [
                    randomKey('5s', false, true),
                    randomKey('5m', false, true)
                ])
                .get('/keys')
                .reply(404);

            return server.register(plugin).then(() => {
                server.auth.strategy('default', 'dynamic-jwt', false, {
                    remoteUri: 'https://example.com/keys'
                });
                server.route({
                    method: 'GET',
                    path: '/protected-route',
                    config: {
                        auth: 'default',
                        handler: (request, reply) => reply(request.auth.credentials)
                    }
                });
                jwtMock.decode.returns({
                    header: {
                        kid: 'f8b86ef5-6f71-40bd-8add-529b4201834c'
                    },
                    payload: {
                        sub: 'sample user'
                    }
                });
                jwtMock.verify.returns();

                return Promise.all([
                    server.inject({
                        url: '/protected-route',
                        headers: {
                            authorization: 'Bearer FOOBARBAZ'
                        }
                    }),
                    server.inject({
                        url: '/protected-route',
                        headers: {
                            authorization: 'Bearer FOOBARBAZ'
                        }
                    })
                ]).then((replies) => {
                    replies.forEach((reply) => {
                        assert.equal(reply.statusCode, 200);
                        assert.property(reply.result, 'sub');
                        assert.equal(reply.result.sub, 'sample user');
                    });
                });
            });
        });

        it('does not expose createJWT or availableKeys', () => {
            nock('https://example.com')
                .get('/keys')
                .reply(200, [
                    randomKey('5s', false, true),
                    randomKey('5m', false, true)
                ]);

            return server.register(plugin).then(() => {
                server.auth.strategy('default', 'dynamic-jwt', false, {
                    remoteUri: 'https://example.com/keys'
                });
                assert.notNestedProperty(server.auth.api, 'default.createJWT');
                assert.notNestedProperty(server.auth.api, 'default.availableKeys');
            });
        });
    });
});
