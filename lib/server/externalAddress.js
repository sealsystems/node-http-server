'use strict';

const consulAdvertiseAddress = require('./consulAdvertiseAddress');

const externalAddress = async function (consul, host) {
  if (!consul) {
    throw new Error('Consul is missing.');
  }
  if (!host) {
    return await consulAdvertiseAddress(consul);
  }

  return host;
};

module.exports = externalAddress;
