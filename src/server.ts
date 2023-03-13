import ws, { type AddressInfo } from "ws";
import { EventEmitter } from "events";
import { Buffer } from "buffer";
import { encode, decode } from "msgpack-lite";

import pkg1 from "kyber-crystals";
import pkg2 from "superdilithium";
const { kyber } = pkg1;
const { superDilithium } = pkg2;

import { randomString, Uint8ArrayToHex, hexToUint8Array } from "./utils.js";

const SubtleCrypto = crypto.subtle;

import ProtoV2dSession from "./session.js";

export interface ServerConfig {
    port: number;
    privateKey: string;
    publicKey: string;
}

export interface ProtoV2dServer extends EventEmitter {
    on(event: "connection", listener: (session: ProtoV2dSession) => void): this;
    emit(event: "connection", session: ProtoV2dSession): boolean;
}

export class ProtoV2dServer extends EventEmitter {
    private wsServer: ws.Server;
    private sessions: Map<string, ProtoV2dSession> = new Map();

    get port() {
        return (this.wsServer.address() as AddressInfo)
            .port;
    }

    constructor(private config: ServerConfig) {
        super();
        this.wsServer = new ws.Server({ port: config.port });
        this.wsServer.on("connection", this.onConnection.bind(this));
    }

    private onConnection(client: ws.WebSocket) {
        let handshaked = false;
        let randomVerifyString = "";
        let asymmKey: { privateKey: Uint8Array, publicKey: Uint8Array } | null = null;
        let encryptionKey: CryptoKey | null = null;
        let oConnection: ProtoV2dSession | null = null;

        client.on("message", async (data: ws.Data) => {
            //console.log("C-[S]", data);
            try {
                let d: Uint8Array;
                if (typeof data === "string") {
                    d = Uint8Array.from(Buffer.from(data));
                } else if (data instanceof ArrayBuffer) {
                    d = new Uint8Array(data);
                } else if (data instanceof Buffer) {
                    d = Uint8Array.from(data);
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

                    //console.log("C*[S]", Buffer.from([d[0], ...new Uint8Array(decryptedData)]));

                    // Decode the data
                    return d[0] === 0x03 ? new Uint8Array(decryptedData) : decode(new Uint8Array(decryptedData));
                })() : decode(d.slice(1)));

                switch (ch) {
                    case 0x02: {
                        if (handshaked) {
                            client.terminate();
                            throw new Error("Handshake already done");
                        }

                        let hsID = dd[0] as number;
                        switch (hsID) {
                            case 1: {
                                let keyPair = await kyber.keyPair();

                                let rootPrivateKey = Uint8Array.from(
                                    Buffer.from(this.config.privateKey, "hex")
                                );

                                let signature = await superDilithium.signDetached(keyPair.publicKey, rootPrivateKey);

                                asymmKey = keyPair;

                                client.send([0x02].concat(Array.from(encode([
                                    2,
                                    Uint8ArrayToHex(keyPair.publicKey),
                                    Uint8ArrayToHex(signature),
                                    this.config.publicKey
                                ]))));
                                break;
                            }

                            case 2: {
                                client.terminate();
                                break;
                            }

                            case 3: {
                                // Decrypt to get AES key
                                let aesKey = await kyber.decrypt(hexToUint8Array(dd[1]), asymmKey!.privateKey);

                                // Import the key
                                encryptionKey = await SubtleCrypto.importKey(
                                    "raw",
                                    aesKey,
                                    "AES-GCM",
                                    true,
                                    ["encrypt", "decrypt"]
                                );

                                // Send test encryption (packet 4)
                                randomVerifyString = randomString(64);
                                let iv = crypto.getRandomValues(new Uint8Array(16));
                                let encryptedData = await SubtleCrypto.encrypt({
                                    name: "AES-GCM",
                                    iv: iv
                                }, encryptionKey, encode([4, randomVerifyString]));

                                client.send([0x02].concat(Array.from(iv), Array.from(new Uint8Array(encryptedData))));
                                break;
                            }

                            case 4: {
                                client.terminate();
                                break;
                            }

                            case 5: {
                                // Verify signature
                                if (await superDilithium.verifyDetached(
                                    Uint8Array.from(
                                        (dd[2].match(/[0-9a-f]{2}/g) ?? []).map((x: string) => parseInt(x, 16))
                                    ),
                                    randomVerifyString,
                                    Uint8Array.from(
                                        (dd[1].match(/[0-9a-f]{2}/g) ?? []).map((x: string) => parseInt(x, 16))
                                    )
                                )) {
                                    // Handshake successful
                                    handshaked = true;
                                    let newSession = false;

                                    // Test if session exists
                                    if (this.sessions.has(dd[1])) {
                                        // Session exists, hook up existing session
                                        oConnection = this.sessions.get(dd[1])!;
                                    } else {
                                        // Session doesn't exist, create new session
                                        oConnection = new ProtoV2dSession(dd[1], false);
                                        this.sessions.set(dd[1], oConnection);

                                        newSession = true;
                                    }

                                    client.on("close", function a() {
                                        client.removeAllListeners();
                                        oConnection.removeListener("data_ret", handleDataSend);
                                        oConnection.removeListener("qos1:queued", handleDataRequeue);
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
                                                if (!oConnection!.qos1Accepted.has(dupID!)) oConnection!.qos1Buffer.push([dupID!, data]);
                                            }, 5000);
                                        } else {
                                            constructedData = Uint8Array.from([
                                                0x00,
                                                ...data
                                            ]);
                                        }

                                        let iv = crypto.getRandomValues(new Uint8Array(16));
                                        let encrypted = await SubtleCrypto.encrypt({
                                            name: "AES-GCM",
                                            iv: iv
                                        }, encryptionKey, constructedData);

                                        client.send(Uint8Array.from([
                                            0x03,
                                            ...iv,
                                            ...new Uint8Array(encrypted)
                                        ]));
                                    }

                                    function handleDataRequeue() {
                                        for (let packet of oConnection!.qos1Buffer) {
                                            handleDataSend(1, packet[1], packet[0]);
                                        }
                                    }

                                    // Hook up the connection
                                    oConnection.on("data_ret", handleDataSend);

                                    // Send all queued data
                                    handleDataRequeue();
                                    oConnection.on("qos1:queued", handleDataRequeue);

                                    let iv = crypto.getRandomValues(new Uint8Array(16));
                                    let encryptedData = await SubtleCrypto.encrypt({
                                        name: "AES-GCM",
                                        iv: iv
                                    }, encryptionKey, encode([6, newSession]));

                                    client.send([0x02].concat(Array.from(iv), Array.from(new Uint8Array(encryptedData))));

                                    setTimeout(() => {
                                        if (newSession)
                                            // Emit connection event
                                            this.emit("connection", oConnection);
                                    }, 50);
                                } else {
                                    // Invalid session ID
                                    client.terminate();
                                }
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
                            let dupID = (dd[1] << 24) | (dd[2] << 16) | (dd[3] << 8) | data[4];
                            if (dd[5] === 0xFF) {
                                // ACK packet
                                oConnection.qos1Accepted.add(dupID);
                            } else {
                                let packetData = dd.slice(6);

                                oConnection.qos1Accepted.add(dupID);
                                oConnection.emit("data", 1, packetData);

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

                                client.send(Uint8Array.from([
                                    0x03,
                                    ...iv,
                                    ...new Uint8Array(encryptedData)
                                ]));
                            }
                        } else {
                            // QoS 0 packet
                            let packetData = dd.slice(1);
                            oConnection.emit("data", 0, packetData);
                        }
                    }
                }
            } catch (e) {
                client.terminate();
                throw e;
            }
        });
    }
}
