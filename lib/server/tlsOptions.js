'use strict';

const getenv = require('getenv');
const tlscert = require('@sealsystems/tlscert');

const log = require('@sealsystems/log').getLogger();

let options;

const createTlsOptions = async function () {
  const ciphers = getenv('TLS_CIPHERS', '');

  if (ciphers) {
    log.info('Explicitly set encryption ciphers.', { ciphers });
  }

  options = await tlscert.get();
  options.ciphers = ciphers;
  options.minVersion = await tlscert.getTlsMinVersion();

  if (options.ca) {
    options.rejectUnauthorized = true;
    options.requestCert = true;
  }

  return options;
};

const tlsOptions = async function () {
  return options || (await createTlsOptions());
};

module.exports = tlsOptions;
