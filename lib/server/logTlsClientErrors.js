'use strict';

const https = require('https');

const values = require('lodash/values');

const log = require('@sealsystems/log').getLogger();

const logTlsClientErrors = function (networkInterfaces) {
  values(networkInterfaces).forEach((nic) => {
    if (!(nic.server instanceof https.Server)) {
      return;
    }

    nic.server.on('tlsClientError', (err) => {
      log.error('A client error occurred while establishing a secure connection.', { err });
    });
  });
};

module.exports = logTlsClientErrors;
