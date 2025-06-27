'use strict';

const assert = require('assertthat');
const proxyquire = require('proxyquire');

const tlscert = require('@sealsystems/tlscert');

const tlsOptions = require('../../lib/server/tlsOptions');

const tlsOptionsMockNoCA = proxyquire('../../lib/server/tlsOptions', {
  '@sealsystems/tlscert': {
    async get() {
      return {};
    }
  }
});
const tlsOptionsMockWithCA = proxyquire('../../lib/server/tlsOptions', {
  '@sealsystems/tlscert': {
    async get() {
      return { ca: 'foo' };
    }
  }
});
const tlsOptionsMockWithCerts = proxyquire('../../lib/server/tlsOptions', {
  '@sealsystems/tlscert': {
    async get() {
      throw new Error('This should not be called.');
    }
  }
});

suite('tlsOptions', () => {
  test('is a function.', async () => {
    assert.that(tlsOptions).is.ofType('function');
  });

  test('throws an error if tlsCert.key is missing.', async () => {
    const keystore = {};
    try {
      await tlsOptionsMockWithCerts(keystore);
      throw new Error('This should not be called.');
    } catch (error) {
      assert.that(error.message).is.equalTo('TLS key is missing.');
    }
  });

  test('throws an error if tlsCert.cert is missing.', async () => {
    const keystore = {
      key: 'foo'
    };
    try {
      await tlsOptionsMockWithCerts(keystore);
      throw new Error('This should not be called.');
    } catch (error) {
      assert.that(error.message).is.equalTo('TLS certificate is missing.');
    }
  });

  test('returns the keystore with default certs.', async () => {
    const keystore = await tlscert.get();
    const options = await tlsOptions();

    assert.that(options.cert).is.equalTo(keystore.cert);
    assert.that(options.key).is.equalTo(keystore.key);
    assert.that(options.ca).is.equalTo(keystore.ca);
  });

  test('returns the keystore given certs.', async () => {
    const keystore = {
      key: 'bla',
      cert: 'blub',
      ca: 'foo'
    };
    const options = await tlsOptionsMockWithCerts(keystore);

    assert.that(options.cert).is.equalTo(keystore.cert);
    assert.that(options.key).is.equalTo(keystore.key);
    assert.that(options.ca).is.equalTo(keystore.ca);
    assert.that(options.requestCert).is.true();
  });

  test('does not return tls ciphers by default.', async () => {
    assert.that((await tlsOptions()).ciphers).is.equalTo('');
  });

  test('does not set CA related options by default.', async () => {
    const actual = await tlsOptionsMockNoCA();

    assert.that(actual.rejectUnauthorized).is.undefined();
    assert.that(actual.requestCert).is.undefined();
  });

  test('does set CA related options by default if CA is provided.', async () => {
    const actual = await tlsOptionsMockWithCA();

    assert.that(actual.rejectUnauthorized).is.true();
    assert.that(actual.requestCert).is.true();
  });

  test('returns minVersion.', async () => {
    const minVersion = await tlscert.getTlsMinVersion();
    const options = await tlsOptions();

    assert.that(options.minVersion).is.equalTo(minVersion);
  });
});
