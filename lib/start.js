'use strict';

const log = require('@sealsystems/log').getLogger();

const create = require('./server/create');

const listen = async function (networkInterfaces, name) {
  const networkInterface = networkInterfaces[name];

  if (!networkInterface) {
    return;
  }

  log.info(`Starting ${name} http server.`, {
    host: networkInterface.host,
    port: networkInterface.port
  });

  networkInterface.server.setTimeout(0);
  networkInterface.server.listen(networkInterface.port, networkInterface.host);
};

const start = async function ({
  app,
  host = undefined,
  port,
  consul,
  requestTimeout,
  headersTimeout,
  tlsCert = undefined
}) {
  if (!app) {
    throw new Error('Express app is missing.');
  }
  if (!port) {
    throw new Error('Port is missing.');
  }
  if (!consul) {
    throw new Error('Consul is missing.');
  }

  const networkInterfaces = await create({ app, host, port, consul, requestTimeout, headersTimeout, tlsCert });

  await listen(networkInterfaces, 'external');
  await listen(networkInterfaces, 'local');

  log.info('All http servers started.');

  return networkInterfaces;
};

module.exports = start;
