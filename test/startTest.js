'use strict';

const util = require('util');

const assert = require('assertthat');
const express = require('express');
const freeport = util.promisify(require('freeport'));
const { nodeenv } = require('nodeenv');
const proxyquire = require('proxyquire');

const externalIp = require('./externalIp');
const start = require('../lib/start');

let errCreate;
const startMock = proxyquire('../lib/start', {
  async './server/create'(options) {
    assert.that(options.consul).is.not.falsy();
    if (errCreate) {
      throw errCreate;
    }
  }
});

suite('start', () => {
  setup(async () => {
    errCreate = null;
  });

  test('is a function.', async () => {
    assert.that(start).is.ofType('function');
  });

  test('throws an error if express app is missing.', async () => {
    await assert
      .that(async () => {
        await start({ host: 'foo', port: 1234 });
      })
      .is.throwingAsync('Express app is missing.');
  });

  test('throws an error if port is missing.', async () => {
    await assert
      .that(async () => {
        await start({ app: {}, host: 'foo' });
      })
      .is.throwingAsync('Port is missing.');
  });

  test('throws an error if consul is missing.', async () => {
    await assert
      .that(async () => {
        await start({ app: {}, host: 'foo', port: 1234 });
      })
      .is.throwingAsync('Consul is missing.');
  });

  test('throws an error if creation of server failed.', async () => {
    const app = express();

    errCreate = new Error('foo');

    await assert
      .that(async () => {
        await startMock({ app, host: externalIp(), port: await freeport(), consul: {} });
      })
      .is.throwingAsync('foo');
  });

  test('starts servers for local and external connections by default.', async () => {
    const app = express();

    const interfaces = await start({ app, host: externalIp(), port: await freeport(), consul: {} });

    assert.that(interfaces.local).is.not.undefined();
    assert.that(interfaces.external).is.not.undefined();

    await Promise.all([
      new Promise((resolve) => interfaces.local.server.close(resolve)),
      new Promise((resolve) => interfaces.external.server.close(resolve))
    ]);
  });

  test('set default for request and headers timeout', async () => {
    const app = express();

    const interfaces = await start({ app, host: externalIp(), port: await freeport(), consul: {} });

    assert.that(interfaces.local.server.requestTimeout).is.equalTo(0);
    assert.that(interfaces.external.server.requestTimeout).is.equalTo(0);
    assert.that(interfaces.local.server.headersTimeout).is.equalTo(0);
    assert.that(interfaces.external.server.headersTimeout).is.equalTo(0);

    await Promise.all([
      new Promise((resolve) => interfaces.local.server.close(resolve)),
      new Promise((resolve) => interfaces.external.server.close(resolve))
    ]);
  });

  test('set request and headers timeout from options', async () => {
    const app = express();

    const interfaces = await start({
      app,
      host: externalIp(),
      port: await freeport(),
      consul: {},
      requestTimeout: 1000,
      headersTimeout: 2000
    });

    assert.that(interfaces.local.server.requestTimeout).is.equalTo(1000);
    assert.that(interfaces.external.server.requestTimeout).is.equalTo(1000);
    assert.that(interfaces.local.server.headersTimeout).is.equalTo(2000);
    assert.that(interfaces.external.server.headersTimeout).is.equalTo(2000);

    await Promise.all([
      new Promise((resolve) => interfaces.local.server.close(resolve)),
      new Promise((resolve) => interfaces.external.server.close(resolve))
    ]);
  });

  test("starts only one server if host is set to '127.0.0.1'", async () => {
    const app = express();

    const interfaces = await start({ app, host: '127.0.0.1', port: await freeport(), consul: {} });

    assert.that(interfaces.local).is.not.null();
    assert.that(interfaces.external).is.undefined();

    await new Promise((resolve) => {
      interfaces.local.server.close(resolve);
    });
  });

  test("starts only one server if host is set to 'localhost'", async () => {
    const app = express();

    const interfaces = await start({ app, host: 'localhost', port: await freeport(), consul: {} });

    assert.that(interfaces.local).is.not.null();
    assert.that(interfaces.external).is.undefined();

    await new Promise((resolve) => {
      interfaces.local.server.close(resolve);
    });
  });

  suite('cloud', () => {
    test('starts only external server for all network interfaces.', async () => {
      const app = express();
      const restore = nodeenv({
        SERVICE_DISCOVERY: 'cloud',
        TLS_UNPROTECTED: 'world'
      });

      const interfaces = await start({
        app,
        host: externalIp(),
        port: 3000,
        consul: {}
      });

      assert.that(interfaces.local).is.undefined();
      assert.that(interfaces.external).is.not.falsy();
      await interfaces.external.server.close();
      restore();
    });
  });
});
