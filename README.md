# js-protov2d

> ⚠️ This package is still in development, but should be usable. Use at your own risk, and please report any bugs you find.

ProtoV2d is a variant of [ProtoV2](https://github.com/BadAimWeeb/js-protov2) protocol, removing libp2p and instead only uses WebSocket to communicate. This results in not being able to seamlessly move the servers, but is much more lightweight and easier to use.

This package will expose a quantum-resistant encrypted tunnel, even when using unsecured WebSocket connections, and can be reconnectable even when using different client IP addresses.

This package works best when used with [DTSocket](https://github.com/BadAimWeeb/js-dtsocket).

## Note on using this package on non-secure contexts in browsers

This package relies heavily on WebCrypto, and it will not available in non-secure contexts. If you want to use this in that case, please add polyfills for WebCrypto.

You can polyfill WebCrypto by using [@peculiar/webcrypto](https://github.com/PeculiarVentures/webcrypto) (`crypto.webcrypto = webcryptoPolyfill`). Make sure to also polyfill node.js crypto ([browserify version](https://github.com/browserify/crypto-browserify)).

## Usage

Install:

```bash
npm install @badaimweeb/js-protov2d
```

Preshared key generation:

```ts
import { keyGeneration } from "@badaimweeb/js-protov2d";

let { privateKey, publicKey, publicKeyHash } = await keyGeneration();
// Note: you should only share public key hash since public key is well over 6kb
```

Server usage:
```ts
import { Server } from "@badaimweeb/js-protov2d";

let server = new Server({
    port: 0, // 0 = random TCP port
    privateKey,
    publicKey
});

let port: number = server.port;

server.on("connection", session => {
    session.on("data", (QoS, data) => {
        // QoS 0: send once
        // QoS 1: send until acknowledged

        // handle data here (data is Uint8Array)
    });

    // send data
    session.send(QoS, data);
});
```

Server usage (with external HTTP(S) server):
```ts
import { createServer as createHTTPServer } from "http";

let httpServer = createHTTPServer();
httpServer.listen(0);

let server = new Server({
    server: httpServer,
    privateKey,
    publicKey
});
```

Server usage (with Express):
```ts
import express from "express";

let app = express();

let server = new Server({
    server: app.listen(0),
    privateKey,
    publicKey
});
```

Client usage:
```ts
import { connect } from "@badaimweeb/js-protov2d";

// If you have public key:
let client = await connect({
    url: `ws://localhost:${port}`,
    publicKey: {
        type: "key",
        key: publicKey
    }
});

// or public key hash:
let client = await connect({
    url: `ws://localhost:${port}`,
    publicKey: {
        type: "hash",
        hash: publicKeyHash
    }
});

// send data
client.send(QoS, data);

// receive data
client.on("data", (QoS, data) => {
    // handle data here (data is Uint8Array)
});
```
