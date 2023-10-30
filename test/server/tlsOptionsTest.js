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

suite('tlsOptions', () => {
  test('is a function.', async () => {
    assert.that(tlsOptions).is.ofType('function');
  });

  test('returns the keystore.', async () => {
    const keystore = await tlscert.get();
    const options = await tlsOptions();

    assert.that(options.cert).is.equalTo(keystore.cert);
    assert.that(options.key).is.equalTo(keystore.key);
    assert.that(options.ca).is.equalTo(keystore.ca);
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
