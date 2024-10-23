'use strict';

const http = require('http');
const https = require('https');

const assert = require('assertthat');
const express = require('express');
const { nodeenv } = require('nodeenv');
const proxyquire = require('proxyquire');

const externalIp = require('../externalIp');

let errExternalAddress;

const create = proxyquire('../../lib/server/create', {
  async './externalAddress'(consul, host) {
    assert.that(consul).is.not.falsy();
    if (errExternalAddress) {
      throw errExternalAddress;
    }

    if (host) {
      return host;
    }

    return externalIp();
  }
});

suite('create', () => {
  setup(async () => {
    errExternalAddress = null;
  });

  test('is a function.', async () => {
    assert.that(create).is.ofType('function');
  });

  test('throws an error if options are missing.', async () => {
    await assert
      .that(async () => {
        await create();
      })
      .is.throwingAsync('Options are missing.');
  });

  test('throws an error if express app is missing.', async () => {
    await assert
      .that(async () => {
        await create({ host: 'foo' });
      })
      .is.throwingAsync('Express app is missing.');
  });

  test('throws an error if Consul is missing.', async () => {
    await assert
      .that(async () => {
        await create({ host: 'foo', app: {} });
      })
      .is.throwingAsync('Consul is missing.');
  });

  test('throws an error if TLS_UNPROTECTED is invalid.', async () => {
    const restore = nodeenv('TLS_UNPROTECTED', 'foo');
    const app = express();

    await assert
      .that(async () => {
        await create({ app, port: 3000, consul: {} });
      })
      .is.throwingAsync('TLS_UNPROTECTED invalid.');

    restore();
  });

  test('throws an error if getting the external address failed.', async () => {
    errExternalAddress = new Error('foo');

    const app = express();

    await assert
      .that(async () => {
        await create({ app, port: 3000, consul: {} });
      })
      .is.throwingAsync('foo');
  });

  test('creates only http servers if TLS_UNPROTECTED=world.', async () => {
    const restore = nodeenv('TLS_UNPROTECTED', 'world');
    const app = express();
    const interfaces = await create({ app, port: 3000, consul: {} });

    assert.that(interfaces.local).is.not.null();
    assert.that(interfaces.local.server).is.instanceOf(http.Server);
    assert.that(interfaces.local.server.requestTimeout).is.equalTo(0);
    assert.that(interfaces.external).is.not.null();
    assert.that(interfaces.external.server).is.instanceOf(http.Server);
    assert.that(interfaces.external.server.requestTimeout).is.equalTo(0);

    await Promise.all([
      new Promise((resolve) => interfaces.local.server.close(resolve)),
      new Promise((resolve) => interfaces.external.server.close(resolve))
    ]);

    restore();
  });

  test('creates https and http servers if TLS_UNPROTECTED=loopback.', async () => {
    const restore = nodeenv('TLS_UNPROTECTED', 'loopback');
    const app = express();
    const interfaces = await create({ app, port: 3000, consul: {} });

    assert.that(interfaces.local).is.not.null();
    assert.that(interfaces.local.server).is.instanceOf(http.Server);
    assert.that(interfaces.external).is.not.null();
    assert.that(interfaces.external.server).is.instanceOf(https.Server);

    await Promise.all([
      new Promise((resolve) => interfaces.local.server.close(resolve)),
      new Promise((resolve) => interfaces.external.server.close(resolve))
    ]);

    restore();
  });

  test('creates only https servers if TLS_UNPROTECTED=none.', async () => {
    const restore = nodeenv('TLS_UNPROTECTED', 'none');
    const app = express();
    const interfaces = await create({ app, port: 3000, consul: {} });

    assert.that(interfaces.local).is.not.null();
    assert.that(interfaces.local.server).is.instanceOf(https.Server);
    assert.that(interfaces.external).is.not.null();
    assert.that(interfaces.external.server).is.instanceOf(https.Server);

    await Promise.all([
      new Promise((resolve) => interfaces.local.server.close(resolve)),
      new Promise((resolve) => interfaces.external.server.close(resolve))
    ]);

    restore();
  });

  test("creates only one server if host is set to '127.0.0.1'", async () => {
    const app = express();
    const interfaces = await create({
      app,
      host: '127.0.0.1',
      port: 3000,
      consul: {}
    });

    assert.that(interfaces.local).is.not.null();
    assert.that(interfaces.local.server).is.not.falsy();
    assert.that(interfaces.external).is.undefined();

    await new Promise((resolve) => {
      interfaces.local.server.close(resolve);
    });
  });

  test("creates only one server if host is set to 'localhost'", async () => {
    const app = express();
    const interfaces = await create({
      app,
      host: 'localhost',
      port: 3000,
      consul: {}
    });

    assert.that(interfaces.local).is.not.falsy();
    assert.that(interfaces.local.server).is.not.falsy();
    assert.that(interfaces.external).is.undefined();

    await new Promise((resolve) => {
      interfaces.local.server.close(resolve);
    });
  });

  test('set requestTimeout if given', async () => {
    const restore = nodeenv('TLS_UNPROTECTED', 'world');
    const app = express();
    const interfaces = await create({ app, port: 3000, consul: {}, requestTimeout: 5000 });

    assert.that(interfaces.local.server.requestTimeout).is.equalTo(5000);
    assert.that(interfaces.external.server.requestTimeout).is.equalTo(5000);

    await Promise.all([
      new Promise((resolve) => interfaces.local.server.close(resolve)),
      new Promise((resolve) => interfaces.external.server.close(resolve))
    ]);

    restore();
  });
});
