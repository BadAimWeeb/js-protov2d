import WebSocket from "isomorphic-ws";

import { encode, decode } from "msgpack-lite";
import { WrappedConnection } from "./connection.js";
import ProtoV2dSession from "./session.js";
import { Buffer } from "buffer";
import { Uint8ArrayToHex, aesDecrypt, aesEncrypt, exactArray, hexToUint8Array, joinUint8Array } from "./utils.js";
import { keyGeneration } from "./keygen.js";

import { NRError } from "./error.js";

import { x25519, ed25519 } from "@noble/curves/ed25519";
import { getDilithium5, getKyber } from "./pqcache.js";

export type ClientCommonConfig = {
    timeout?: number,
    publicKeys: ({
        type: "key",
        value: string | Uint8Array
    } | {
        type: "hash",
        value: string | Uint8Array
    })[] | [{
        type: "noverify"
    }],
    disableEncryption?: boolean,
    existingData?: {
        sessionKey?: Uint8Array,
        sessionID?: Uint8Array
        sessionObject?: ProtoV2dSession
    },
    handshakeV1?: "disabled" | "forced" | "auto",
    disableWASM?: boolean
}

export type ClientWSConfig = ClientCommonConfig & { url: string };
export type ClientWCConfig<BackendData = any> = ClientCommonConfig & { wc: WrappedConnection<BackendData> };

/** 
 * Connect to a ProtoV2d server over WebSocket. 
 * 
 * By default, `reconnectionTime` is 5s, this means that it will retry connection every 5s if the connection is closed; `timeout` is 10s.
 */
export function connect(config: ClientWSConfig & { reconnectionTime?: number, maxInitialRetries?: number }) {
    return connectWithCustomConnect(config, connectWebsocket);
}

/** 
 * Connect to a ProtoV2d server with your own protocol. This will handle reconnection for you.
 * 
 * By default, `reconnectionTime` is 5s, this means that it will retry connection every 5s if the connection is closed; `timeout` is 10s.
 */
export async function connectWithCustomConnect<CustomConfig, BackendData>(
    config: ClientCommonConfig & CustomConfig & { reconnectionTime?: number, maxInitialRetries?: number },
    connectFunc: (config: ClientCommonConfig & CustomConfig) => Promise<ProtoV2dSession<BackendData>>
) {
    let sessionKey: Uint8Array | undefined = void 0, sessionID: Uint8Array | undefined = void 0;
    let sessionObject: ProtoV2dSession<BackendData> | undefined = void 0;
    if (config.existingData) {
        if ("sessionID" in config.existingData && config.existingData.sessionID) {
            sessionID = config.existingData.sessionID;
        } else if ("sessionObject" in config.existingData && config.existingData.sessionObject) {
            sessionID = hexToUint8Array(config.existingData.sessionObject.connectionPK);
            sessionObject = config.existingData.sessionObject;
        }

        if (config.existingData.sessionKey) {
            sessionKey = config.existingData.sessionKey;
        }
    }

    if (!sessionKey || !sessionID) {
        let keyGen = await keyGeneration();
        sessionKey = hexToUint8Array(keyGen.privateKey);
        sessionID = hexToUint8Array(keyGen.publicKey);
    }

    let err: any = void 0;
    for (let r = 0; r < (config.maxInitialRetries ?? Infinity); r++) {
        try {
            let baseSession = await connectFunc({
                ...config,
                existingData: {
                    sessionKey,
                    sessionID,
                    sessionObject
                }
            });
            sessionObject = baseSession;

            baseSession.wc!.once("close", async () => {
                for (; ;)
                    try {
                        await connectFunc({
                            ...config,
                            existingData: {
                                sessionKey,
                                sessionID,
                                sessionObject
                            }
                        });

                        return;
                    } catch {
                        await new Promise<void>(r => setTimeout(r, config.reconnectionTime || 5000));
                    }
            });

            return baseSession;
        } catch (e) {
            if (e instanceof NRError) throw e;
            err = e;
            await new Promise<void>(r => setTimeout(r, config.reconnectionTime || 5000));
        }
    }

    let e = new NRError("Failed to connect after maximum retries");
    e.cause = err;

    throw e;
}

/** This does not implement reconnection. You should not use this directly, use {@link connect} instead. */
export function connectWebsocket(config: ClientWSConfig) {
    return new Promise<ProtoV2dSession<WebSocket>>(async (resolve, reject) => {
        let ws = new WebSocket(config.url);
        ws.binaryType = "arraybuffer";

        // Client side cannot access real server IP.
        let wc = new WrappedConnection(null, ws);

        function handleError(err: WebSocket.ErrorEvent) {
            reject(err);
            ws.removeEventListener("error", handleError);
            ws.removeEventListener("close", handleClose);
            ws.removeEventListener("message", handleData);
        }

        function handleClose(e: WebSocket.CloseEvent) {
            reject(new Error(e.reason));
            ws.removeEventListener("error", handleError);
            ws.removeEventListener("close", handleClose);
            ws.removeEventListener("message", handleData);
        }

        async function handleData(e: WebSocket.MessageEvent) {
            let eData = e.data;
            let d: Uint8Array;
            if (eData instanceof ArrayBuffer) d = new Uint8Array(eData);
            else if (typeof eData === "string") {
                let enc = new TextEncoder();
                d = enc.encode(eData);
            }
            else if (eData instanceof Blob) d = new Uint8Array(await eData.arrayBuffer()); // redundant
            else if (eData instanceof Buffer) d = new Uint8Array(eData); // redundant
            else if (Array.isArray(eData)) { // redundant
                d = joinUint8Array(...eData.map(x => new Uint8Array(x.buffer, x.byteOffset, x.byteLength)));
            }
            else throw new Error("Unknown data type");

            wc.emit("rx", d);
        }

        ws.addEventListener("error", handleError);
        ws.addEventListener("close", handleClose);
        ws.addEventListener("message", handleData);
        await new Promise<void>(r => ws.addEventListener("open", () => r()));

        return connectWrapped({ ...config, wc });
    });
}

/** 
 * This does not implement reconnection. You should only use this when using custom protocol, and you must self-handle session key/ID. 
 * 
 * Alternatively, make a function that wrap connection to {@link WrappedConnection} and use {@link connectWithCustomConnect} instead.
 */
export function connectWrapped<BackendData>(config: ClientWCConfig<BackendData>) {
    return new Promise<ProtoV2dSession<BackendData>>(async (resolve, reject) => {
        //#region State variables
        let state = {
            version: 0,
            currentPacket: 0,
            encryption: false,
            handshaked: false
        };

        if (!config.existingData || !config.existingData.sessionKey || !config.existingData.sessionID) {
            reject(new NRError("Missing session key/ID")); return;
        }

        if (!["auto", "disabled", "forced"].includes(config.handshakeV1 || "auto")) {
            reject(new NRError("v1 handshake option is invalid")); return;
        }

        let noVerify = !!config.publicKeys.find(x => x.type === "noverify");
        let pkValues: [isHash: boolean, Uint8Array][] = [];
        if (!noVerify) {
            for (let pk of config.publicKeys) {
                if (pk.type === "key") {
                    pkValues.push([false, typeof pk.value === "string" ? hexToUint8Array(pk.value) : pk.value]);
                } else if (pk.type === "hash") {
                    pkValues.push([true, typeof pk.value === "string" ? hexToUint8Array(pk.value) : pk.value]);
                }
            }
        }
        let isFullKeyOnly = pkValues.every(x => !x[0]);

        let wc = config.wc;
        if (!wc) {
            reject(new NRError("Missing wrapped connection")); return;
        }

        let sessionKey = config.existingData.sessionKey;
        let sessionID = config.existingData.sessionID;
        let sessionObject: ProtoV2dSession<BackendData> | undefined = config.existingData.sessionObject;
        let timeout = config.timeout || 10000;

        if (sessionObject && (sessionObject.connectionPK !== Uint8ArrayToHex(sessionID))) {
            reject(new NRError("Session ID mismatch")); return;
        }

        let encryptionKeyPQ: CryptoKey | null = null;
        let encryptionKeyClassic: CryptoKey | null = null;

        let dilithium5 = await getDilithium5(!!config.disableWASM);
        let kyber = await getKyber(!!config.disableWASM);

        function rejectHandshake(reason: string, nonRecoverable = false) {
            reject(nonRecoverable ? new NRError(reason) : new Error(reason));
            wc.emit("close");
            wc.removeListener("rx", onIncomingData);
        }

        async function onIncomingData(data: Uint8Array) {
            if (!state.handshaked && data[0] !== 0x02) {
                rejectHandshake("Invalid data during handshake"); return;
            }

            if (state.version === 0) {
                // Determine version by looking at data
                if (data[1] === 0x94) state.version = 1;
                else if (data[1] === 0x02) state.version = 2;
                else {
                    rejectHandshake("Unknown version"); return;
                };
            }

            if (state.version === 1 && config.handshakeV1 === "disabled") {
                rejectHandshake("v1 handshake is disabled"); return;
            }

            switch (state.version) {
                case 1: {
                    switch (state.currentPacket) {
                        case 1: {
                            let packet = decode(data.slice(1)) as [2, string, string, string];
                            if (packet[0] !== 2) {
                                rejectHandshake("Invalid packet"); return;
                            }

                            let pqPK = hexToUint8Array(packet[1]);

                            if (!noVerify) {
                                let signature = hexToUint8Array(packet[2]);
                                let signaturePK = hexToUint8Array(packet[3]);
                                let signaturePKH = isFullKeyOnly ? null : new Uint8Array(await crypto.subtle.digest("SHA-256", signaturePK));

                                if (!pkValues.some(v => {
                                    if (v[0]) return exactArray(v[1], signaturePKH!);
                                    else return exactArray(v[1], signaturePK);
                                })) {
                                    rejectHandshake("No public key matches"); return;
                                }

                                
                                let verified = await dilithium5.verify(signature, pqPK, signaturePK);

                                if (!verified) {
                                    rejectHandshake("New public key signature verification failed"); return;
                                }
                            }

                            
                            let enc = await kyber.encapsulate(pqPK);

                            encryptionKeyPQ = await crypto.subtle.importKey("raw", enc.sharedSecret, "AES-GCM", false, ["encrypt", "decrypt"]);

                            state.currentPacket = 2;
                            wc.send(joinUint8Array([0x02], encode([3, enc.ciphertext])));
                            break;
                        }

                        case 2: {
                            let packet = decode(await aesDecrypt(data.slice(1), encryptionKeyPQ!, false)) as [4, string];
                            if (packet[0] !== 4) {
                                rejectHandshake("Invalid packet"); return;
                            }

                            let encoder = new TextEncoder();
                            let rnd = encoder.encode(packet[1]);

                            let sessionKeyClassic = sessionKey.slice(0, 32);
                            let sessionKeyPQ = sessionKey.slice(32);

                            let signature = Uint8ArrayToHex(ed25519.sign(rnd, sessionKeyClassic)) + Uint8ArrayToHex((await dilithium5.sign(rnd, sessionKeyPQ)).signature);

                            state.currentPacket = 3;
                            wc.send(joinUint8Array([0x02], await aesEncrypt(encode([5, sessionID, signature]), encryptionKeyPQ!, false)));
                            break;
                        }

                        case 3: {
                            let packet = decode(await aesDecrypt(data.slice(1), encryptionKeyPQ!, false)) as [6, boolean];
                            if (packet[0] !== 6) {
                                rejectHandshake("Invalid packet"); return;
                            }

                            state.handshaked = true;
                            state.currentPacket = 4;

                            if (packet[1]) {
                                let newSession = new ProtoV2dSession(Uint8ArrayToHex(sessionID), 1, true, wc, [encryptionKeyPQ!], timeout);
                                if (sessionObject) {
                                    sessionObject.emit("resumeFailed", newSession);
                                    sessionObject.close();
                                }

                                sessionObject = newSession;
                            } else {
                                if (!sessionObject) {
                                    sessionObject = new ProtoV2dSession(Uint8ArrayToHex(sessionID), 1, true, wc, [encryptionKeyPQ!], timeout);
                                } else {
                                    sessionObject.protocolVersion = 1;
                                    sessionObject.encryption = [encryptionKeyPQ!];
                                    sessionObject.wc = wc;
                                }
                            }

                            resolve(sessionObject);
                            // handshake done
                            wc.removeListener("rx", onIncomingData);
                            break;
                        }
                    }
                    break;
                }

                case 2: {
                    break;
                }
            }
        }

        wc.on("rx", onIncomingData);

        if (config.handshakeV1 === "forced") {
            state.version = 1;
            state.currentPacket = 1;
            wc.send(encode([1, 1]));
        } else {
            state.version = config.handshakeV1 === "disabled" ? 2 : 0;
            state.currentPacket = 1;
            wc.send(joinUint8Array([0x02], encode([1, 2, [2], config.disableEncryption ? 2 : (isFullKeyOnly ? 0 : 1)])));
        }
    });
}
