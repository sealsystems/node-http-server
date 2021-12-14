'use strict';

const os = require('os');

const flatten = require('lodash/flatten');
const values = require('lodash/values');

const externalIp = function () {
  const nics = os.networkInterfaces();

  return flatten(values(nics)).find((address) => address.family === 'IPv4' && !address.internal).address;
};

module.exports = externalIp;
