import { connect, Server } from "../index.js";
import { Buffer } from "buffer";

import pkg from "superdilithium";
const { superDilithium } = pkg;
let keyPair = await superDilithium.keyPair();

let server = new Server({
    port: 0,
    privateKey: Array.from(keyPair.privateKey).map((x) => x.toString(16).padStart(2, "0")).join(""),
    publicKey: Array.from(keyPair.publicKey).map((x) => x.toString(16).padStart(2, "0")).join("")
});

// Get port 
let port = server.port;
console.log("Server listening on port", port);

let randomData = crypto.getRandomValues(new Uint8Array(8));
console.log("Test data:           ", randomData);

server.on("connection", session => {
    session.on("data", (QoS, data) => {
        console.log("Got data from client:", data);
        session.send(1, data);
    });
});

// Create client
let client = await connect({
    url: `ws://localhost:${port}`,
    publicKey: {
        type: "key",
        key: Array.from(keyPair.publicKey).map((x) => x.toString(16).padStart(2, "0")).join("")
    }
});

// Send data test
client.send(1, randomData);
client.on("data", (QoS, data) => {
    console.log("Got data from server:", data);
    if (JSON.stringify(Array.from(data)) === JSON.stringify(Array.from(randomData))) {
        console.log("Test passed!");
        process.exit(0);
    } else {
        console.log("Test failed!");
        process.exit(1);
    }
});
