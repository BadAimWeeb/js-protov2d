import WebSocket from "isomorphic-ws";

import { Buffer } from "buffer";
import { encode, decode } from "msgpack-lite";

import pkg1 from "kyber-crystals";
import pkg2 from "superdilithium";
const { kyber } = pkg1;
const { superDilithium } = pkg2;

const SubtleCrypto = crypto.subtle;

import ProtoV2dSession from "./session.js";
import { hexToUint8Array, Uint8ArrayToHex } from "./utils.js";

export interface ClientConfig {
    url: string,
    publicKey: {
        type: "key",
        key: string
    } | {
        type: "hash",
        hash: string
    }
}

export function connect(config: ClientConfig, reconnectionData?: {
    sessionKey: Uint8Array,
    sessionID: Uint8Array,
    sessionInstance: ProtoV2dSession
}) {
    return new Promise<ProtoV2dSession>(async (resolve, reject) => {
        let ws = new WebSocket(config.url);

        let closed = false;
        let handshaked = false;
        let encryptionKey: CryptoKey | null = null;

        let sessionKey: Uint8Array;
        let sessionID: Uint8Array;
        let sessionInstance: ProtoV2dSession;

        if (reconnectionData) {
            sessionKey = reconnectionData.sessionKey;
            sessionID = reconnectionData.sessionID;
            sessionInstance = reconnectionData.sessionInstance;
        } else {
            let keyPair = await superDilithium.keyPair();
            sessionKey = keyPair.privateKey;
            sessionID = keyPair.publicKey;

            sessionInstance = new ProtoV2dSession(Array.from(sessionID).map(x => x.toString(16).padStart(2, "0")).join(""), true);
        }

        ws.addEventListener("open", () => {
            ws.send(Uint8Array.from([0x02, 0x92, 0x01, 0x01]));
        });

        ws.addEventListener("message", async data => {
            //console.log("S-[C]", data);
            try {
                let d: Uint8Array;
                if (typeof data.data === "string") {
                    d = Uint8Array.from(Buffer.from(data.data, "utf-8"));
                } else if (data.data instanceof ArrayBuffer) {
                    d = new Uint8Array(data.data);
                } else if (data.data instanceof Buffer) {
                    d = Uint8Array.from(data.data);
                } else {
                    console.error(data);
                    throw new Error("Buffer[] Not implemented");
                }

                let ch = d[0];
                let dd = await (encryptionKey ? (async () => {
                    // First 16 bytes are the IV, excluding the first byte
                    let iv = d.slice(1, 17);

                    // The rest is the encrypted data
                    let encryptedData = d.slice(17);

                    // Decrypt the data
                    let decryptedData = await SubtleCrypto.decrypt({
                        name: "AES-GCM",
                        iv: iv
                    }, encryptionKey, encryptedData);

                    //console.log("S*[C]", Buffer.from([d[0], ...new Uint8Array(decryptedData)]));

                    // Decode the data
                    return d[0] === 0x03 ? new Uint8Array(decryptedData) : decode(new Uint8Array(decryptedData));
                })() : decode(d.slice(1)));

                switch (ch) {
                    case 0x02: {
                        if (handshaked) {
                            ws.terminate();
                            throw new Error("Handshake already done");
                        }

                        let hsID = dd[0] as number;
                        switch (hsID) {
                            case 1: {
                                // not server, rejecting
                                ws.terminate();
                                reject(new Error("Invalid handshake: Server OP received"));
                                return;
                            }

                            case 2: {
                                // verifying server key
                                let newPK = dd[1] as string;
                                let signature = dd[2] as string;
                                let rootPK = dd[3] as string;

                                let rootPKHash = Array.from(new Uint8Array(await SubtleCrypto.digest(
                                    "SHA-256",
                                    hexToUint8Array(rootPK)
                                ))).map(x => x.toString(16).padStart(2, "0")).join("");

                                // Comparing key
                                if (config.publicKey.type === "key") {
                                    if (rootPK !== config.publicKey.key) {
                                        ws.terminate();
                                        reject(new Error("Invalid handshake: Server key mismatch"));
                                        return;
                                    }
                                } else if (config.publicKey.type === "hash") {
                                    if (rootPKHash !== config.publicKey.hash) {
                                        ws.terminate();
                                        reject(new Error("Invalid handshake: Server key mismatch"));
                                        return;
                                    }
                                }

                                let signatureArray = hexToUint8Array(signature);
                                let newPKArray = hexToUint8Array(newPK);
                                let rootPKArray = hexToUint8Array(rootPK);

                                // Verifying signature
                                if (await superDilithium.verifyDetached(signatureArray, newPKArray, rootPKArray) === false) {
                                    ws.terminate();
                                    reject(new Error("Invalid handshake: Invalid server signature"));
                                    return;
                                }

                                // Generating new key
                                let key = await kyber.encrypt(newPKArray);
                                let cipherString = Uint8ArrayToHex(key.cyphertext);
                                encryptionKey = await SubtleCrypto.importKey("raw", key.secret, "AES-GCM", false, ["encrypt", "decrypt"]);

                                // Sending key
                                ws.send(Uint8Array.from([0x02].concat(Array.from(encode([3, cipherString])))));

                                break;
                            }

                            case 3: {
                                // not server, rejecting
                                ws.terminate();
                                reject(new Error("Invalid handshake: Server OP received"));
                                return;
                            }

                            case 4: {
                                // Init session
                                let randomString = dd[1] as string;

                                // Create signature for session
                                let signature = await superDilithium.signDetached(randomString, sessionKey);

                                // Create encrypted data
                                let iv = crypto.getRandomValues(new Uint8Array(16));
                                let encryptedData = new Uint8Array(
                                    await SubtleCrypto.encrypt({
                                        name: "AES-GCM",
                                        iv: iv
                                    }, encryptionKey, encode([
                                        5,
                                        Array.from(sessionID).map(x => x.toString(16).padStart(2, "0")).join(""),
                                        Array.from(signature).map(x => x.toString(16).padStart(2, "0")).join("")
                                    ]))
                                );

                                // Send encrypted data
                                ws.send(Uint8Array.from([0x02].concat(Array.from(iv), Array.from(encryptedData))));
                                break;
                            }

                            case 5: {
                                // not server, rejecting
                                ws.terminate();
                                reject(new Error("Invalid handshake: Server OP received"));
                                return;
                            }

                            case 6: {
                                handshaked = true;
                                resolve(sessionInstance);

                                ws.on("close", function a() {
                                    ws.removeAllListeners();
                                    sessionInstance.removeListener("data_ret", handleDataSend);
                                    sessionInstance.removeListener("qos1:queued", handleDataRequeue);

                                    // reconnect
                                    connect(config, {
                                        sessionKey: sessionKey,
                                        sessionID: sessionID,
                                        sessionInstance: sessionInstance
                                    }).catch(() => {
                                        setTimeout(a, 5000);
                                    });
                                });

                                async function handleDataSend(qos: number, data: Uint8Array, dupID?: number) {
                                    let constructedData: Uint8Array;
                                    if (qos === 1) {
                                        constructedData = Uint8Array.from([
                                            0x01,
                                            (dupID! >> 24) & 0xFF,
                                            (dupID! >> 16) & 0xFF,
                                            (dupID! >> 8) & 0xFF,
                                            dupID! & 0xFF,
                                            0x00,
                                            ...data
                                        ]);

                                        // Re-add the data to the queue if no ack is received
                                        setTimeout(() => {
                                            if (!sessionInstance!.qos1Accepted.has(dupID!)) sessionInstance!.qos1Buffer.push([dupID!, data]);
                                        }, 5000);
                                    } else {
                                        constructedData = Uint8Array.from([
                                            0x00,
                                            ...data
                                        ]);
                                    }

                                    if (!closed) {
                                        let iv = crypto.getRandomValues(new Uint8Array(16));
                                        let encrypted = await SubtleCrypto.encrypt({
                                            name: "AES-GCM",
                                            iv: iv
                                        }, encryptionKey, constructedData);

                                        ws.send(Uint8Array.from([
                                            0x03,
                                            ...iv,
                                            ...new Uint8Array(encrypted)
                                        ]));
                                    }
                                }

                                function handleDataRequeue() {
                                    for (let packet of sessionInstance!.qos1Buffer) {
                                        handleDataSend(1, packet[1], packet[0]);
                                    }
                                }

                                // Hook up the connection
                                sessionInstance.on("data_ret", handleDataSend);

                                // Send all queued data
                                handleDataRequeue();
                                sessionInstance.on("qos1:queued", handleDataRequeue);
                                break;
                            }

                            default: {
                                ws.terminate();
                                reject(new Error("Invalid handshake: Unknown OP"));
                                return;
                            }
                        }

                        break;
                    }

                    case 0x03: {
                        if (!handshaked) {
                            return;
                        }

                        if (dd[0] === 1) {
                            // QoS 1 packet
                            let dupID = (dd[1] << 24) | (dd[2] << 16) | (dd[3] << 8) | dd[4];
                            if (dd[5] === 0xFF) {
                                // ACK packet
                                sessionInstance.qos1Accepted.add(dupID);
                            } else {
                                let packetData = dd.slice(6);

                                sessionInstance.qos1Accepted.add(dupID);
                                sessionInstance.emit("data", 1, packetData);

                                // Send ACK
                                let iv = crypto.getRandomValues(new Uint8Array(16));
                                let encryptedData = await SubtleCrypto.encrypt({
                                    name: "AES-GCM",
                                    iv: iv
                                }, encryptionKey, Uint8Array.from([
                                    1,
                                    (dupID >> 24) & 0xFF,
                                    (dupID >> 16) & 0xFF,
                                    (dupID >> 8) & 0xFF,
                                    dupID & 0xFF,
                                    0xFF
                                ]));

                                ws.send(Uint8Array.from([
                                    0x03,
                                    ...iv,
                                    ...new Uint8Array(encryptedData)
                                ]));
                            }
                        } else {
                            // QoS 0 packet
                            let packetData = dd.slice(1);
                            sessionInstance.emit("data", 0, packetData);
                        }
                    }
                }
            } catch { }
        });
    });
}