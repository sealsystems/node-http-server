'use strict';

const getenv = require('@sealsystems/seal-getenv');
const tlscert = require('@sealsystems/tlscert');

const log = require('@sealsystems/log').getLogger();

let options;

const createTlsOptions = async function (tlsCert) {
  if (tlsCert) {
    if (!tlsCert.key) {
      throw new Error('TLS key is missing.');
    }
    if (!tlsCert.cert) {
      throw new Error('TLS certificate is missing.');
    }
  }
  const ciphers = getenv('TLS_CIPHERS', '');

  if (ciphers) {
    log.info('Explicitly set encryption ciphers.', { ciphers });
  }

  options = tlsCert || (await tlscert.get());
  options.ciphers = ciphers;
  options.minVersion = await tlscert.getTlsMinVersion();

  if (options.ca) {
    options.rejectUnauthorized = true;
    options.requestCert = true;
  }

  return options;
};

const tlsOptions = async function (tlsCert) {
  return options || (await createTlsOptions(tlsCert));
};

module.exports = tlsOptions;
