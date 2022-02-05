# @sealsystems/http-server



@sealsystems/http-server serves an [Express](https://expressjs.com) app. It accepts local HTTP connections and HTTPS-encrypted connections from any given external interface.

## Installation

```shell
$ npm install @sealsystems/http-server
```

## Quick start

First you need to add a reference to @sealsystems/http-server within your application:

```javascript
const httpServer = require('@sealsystems/http-server');
```

### Starting the server

Create an Express app to define the routes that should be handled:

```javascript
const express = require('express');
const myExpressApp = express();

myExpressApp.get('/', function(req, res){
  res.send('hello world');
});
```

Then, create an `options` object:

```javascript
const options = {
  app: myExpressApp,
  host: '192.168.0.1',
  port: '3000',
  consul
};
```

`host` is the hostname or the IP address of the external interface you want the server to bind to. Regardless of the `host` value it will also bind to `localhost`. Both, local and external connections use the given `port`. If you ommit the property `host`, the address that is advertised by Consul will be used as the external interface. See Consul's docs for more information about its [`advertise_addr` setting](https://www.consul.io/docs/agent/options.html#advertise_addr).
`consul` is an initialized [`node-consul`](https://github.com/sealsystems/node-consul) object. 

Finally, call the `start` function:

```javascript
const serverList = await httpServer.start(options);
console.log('Http server is listening', options);
```

The return parameter `serverList` is an array, containing all started http servers.

### Shutting down the server

Before you exit the application, you can perform a graceful shutdown. In this case, no new connection will be accepted by the server. The function returns once all already open connections are closed. Thus, no connection will be dropped by the server.

To perform a graceful shutdown, call the `shutdown` function:

```javascript
await httpServer.shutdown();

console.log('Http server is shut down.');
```

## Environment variables

For connections via HTTPS you can define the set of allowed ciphers by setting the environment variable `TLS_CIPHERS`.  

`TLS_UNPROTECTED` controls which connections are encrypted:

- `none`

  Local and external connections are encrypted via HTTPS. This is the most secure setting but decreases the performance to some extend.

- `loopback`

  Local connections are served via HTTP. External connections are encrypted via HTTPS. This is the default setting.

- `world`

  Local and external connections are served via HTTP. **This is insecure!**

`SERVICE_DISCOVERY=cloud` and `TLS_UNPROTECTED=world` together uses one HTTP server for all network interfaces. This is used in cloud scenarios where we have a secure internal network.

## Technical details

In order to handle traffic coming through the local and the given external interface(s), two server objects will be created: One binds to the local interface, the other one binds to the given external interface(s). Both servers use the same port. This also allows e.g. to use HTTP locally but to encrypt external connections via HTTPS.

For bookkeeping purposes the server objects are stored as properties of the `instances` variable in [lib/httpServer.js](lib/httpsServer.js).

```javascript
const instances = {
  external: <external server object>,
  local: <local server object>
};
```

Depending on the environment variable `TLS_UNPROTECTED`, the server objects will be of type `Http` or `Https`.

If `host` in the options of the `start` function is set to `localhost` or `127.0.0.1`, only the local server will be created. The `instances` variable will look like:

```javascript
const instances = {
  local: <local server object>
};
```

## Running the build

To build this module use [roboter](https://www.npmjs.com/package/roboter).

```bash
$ bot
```
