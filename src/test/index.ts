import { AddressInfo } from "ws";
import { connect, Server, keyGeneration } from "../index.js";

import { aesEncrypt, aesDecrypt } from "../utils.js";

let randomKey = crypto.subtle.importKey("raw", crypto.getRandomValues(new Uint8Array(32)), "AES-GCM", false, ["encrypt", "decrypt"]);
let r = crypto.getRandomValues(new Uint8Array(32));
let encrypted = await aesEncrypt(r, await randomKey, true);
let decrypted = await aesDecrypt(encrypted, await randomKey, true);
if (JSON.stringify(Array.from(r)) !== JSON.stringify(Array.from(decrypted))) {
    console.log("AES-GCM test failed!");
    process.exit(1);
}

let k = await keyGeneration();

let server = new Server({
    port: 0,
    privateKey: k.privateKey,
    publicKey: k.publicKey,
    allowDisableEncryption: true
});

// Get port 
let port = (server.wsServer.address() as AddressInfo).port;
console.log("Server listening on port", port);

let randomData = crypto.getRandomValues(new Uint8Array(8));
console.log("Test data:           ", randomData);

server.on("connection", session => {
    console.log("Server received connection.");
    session.on("data", (QoS, data) => {
        console.log("Got data from client:", data);
        session.send(1, data);
    });
});

// Create client 1
let client = await connect({
    url: `ws://localhost:${port}`,
    publicKeys: [{
        type: "key",
        value: k.publicKey
    }],
    maxInitialRetries: 1
});

console.log("Client 1 established connection.");

// Send data test
await new Promise<void>(r => {
    let ack = client.send(1, randomData);
    client.on("data", async (QoS, data) => {
        await ack;
        console.log("Got data from server:", data);

        if (JSON.stringify(Array.from(data)) === JSON.stringify(Array.from(randomData))) {
            console.log("Test 1 passed");
            r();
        } else {
            console.log("Test 1 failed");
            process.exit(1);
        }
    });
});
client.close();

// Create client 2 (v1 forced)
let client2 = await connect({
    url: `ws://localhost:${port}`,
    publicKeys: [{
        type: "key",
        value: k.publicKey
    }],
    maxInitialRetries: 1,
    handshakeV1: "forced"
});

console.log("Client 2 established connection.");

// Send data test
await new Promise<void>(r => {
    let ack = client2.send(1, randomData);
    client2.on("data", async (QoS, data) => {
        await ack;
        console.log("Got data from server:", data);

        if (JSON.stringify(Array.from(data)) === JSON.stringify(Array.from(randomData))) {
            console.log("Test 2 passed");
            r();
        } else {
            console.log("Test 2 failed");
            process.exit(1);
        }
    });
});
client2.close();

// Create client 3 (v2, encryption disabled)
let client3 = await connect({
    url: `ws://localhost:${port}`,
    publicKeys: [{
        type: "key",
        value: k.publicKey
    }],
    maxInitialRetries: 1,
    disableEncryption: true
});

console.log("Client 3 established connection.");

// Send data test
await new Promise<void>(r => {
    let ack = client3.send(1, randomData);
    client3.on("data", async (QoS, data) => {
        await ack;
        console.log("Got data from server:", data);

        if (JSON.stringify(Array.from(data)) === JSON.stringify(Array.from(randomData))) {
            console.log("Test 3 passed");
            r();
        } else {
            console.log("Test 3 failed");
            process.exit(1);
        }
    });
});

let client4 = await connect({
    url: `wss://edge1-status.badaimweeb.me/`,
    publicKeys: [{
        type: "noverify"
    }],
    maxInitialRetries: 1
});

console.log("All test passed!");
process.exit(0);
