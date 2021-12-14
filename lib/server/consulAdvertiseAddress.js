'use strict';

const consulAdvertiseAddress = async function (consul) {
  if (!consul) {
    throw new Error('Consul is missing.');
  }
  const memberInfo = await consul.getMember();

  if (!memberInfo || !memberInfo.Addr) {
    throw new Error('Invalid information from Consul received.');
  }

  return memberInfo.Addr;
};

module.exports = consulAdvertiseAddress;
