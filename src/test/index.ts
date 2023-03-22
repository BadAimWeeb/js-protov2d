import { connect, Server, keyGeneration } from "../index.js";

let k = await keyGeneration();

let server = new Server({
    port: 0,
    privateKey: k.privateKey,
    publicKey: k.publicKey
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
        key: k.publicKey
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
