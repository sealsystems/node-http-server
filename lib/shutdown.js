'use strict';

const shutdown = async function (servers) {
  if (!servers) {
    throw new Error('Servers are missing.');
  }

  const serverNames = Object.keys(servers);

  await Promise.all(
    serverNames.map((serverName) => {
      const server = servers[serverName];

      return new Promise((resolve) => {
        server.close(() => resolve());
      });
    })
  );
};

module.exports = shutdown;
