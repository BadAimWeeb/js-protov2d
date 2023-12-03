import WebSocket from "isomorphic-ws";

import { encode, decode } from "msgpack-lite";
import { WrappedConnection } from "./connection.js";
import ProtoV2dSession from "./session.js";
import { Buffer } from "buffer";
import { Uint8ArrayToHex, aesDecrypt, aesEncrypt, exactArray, filterNull, hexToUint8Array, joinUint8Array, SHA512_NULL } from "./utils.js";
import { keyGeneration } from "./keygen.js";

import { NRError } from "./error.js";

import { x25519, ed25519 } from "@noble/curves/ed25519";
import { getDilithium5, getKyber } from "./pqcache.js";

import debug from "debug";
const log = debug("protov2d:client");

export type ClientCommonConfig = {
    /** How long after pinging should the connection be considered disconnected. (ms) */
    timeout?: number,
    /** How frequent to ping the other server. Lower value mean more frequent ping and more frequent latency value updates. (ms) */
    pingInterval?: number,
    publicKeys: ({
        type: "key",
        value: string | Uint8Array
    } | {
        type: "hash",
        value: string | Uint8Array
    } | {
        type: "noverify"
    })[],
    /** NOT RECOMMENDED: Only use this when debugging, as your data is transmitted as cleartext if there's no additional encryption layer (TLS) and is viewable using DevTools. */
    disableEncryption?: boolean,
    existingData?: {
        sessionKey?: Uint8Array,
        sessionID?: Uint8Array
        sessionObject?: ProtoV2dSession
    },
    handshakeV1?: "disabled" | "forced" | "auto",
    /** In case you're sure that the enviroment cannot run WASM at all, you can disable it. */
    disableWASM?: boolean
}

export type ClientWSConfig = ClientCommonConfig & { url: string };
export type ClientWCConfig<BackendData = any> = ClientCommonConfig & { wc: WrappedConnection<BackendData> };

export type ClientReconnectConfig = {
    /** How long between two connection attempt. (ms) */
    reconnectionTime?: number,
    /** How many times to attempt to connect initially before giving up. */
    maxInitialRetries?: number,
    /** 
     * Should the client attempt to reconnect no matter what?
     * 
     * If set to true, .close() will instead restart the connection, not disconnecting session. NOT RECOMMENDED UNLESS CLIENT NEEDS TO BE ALWAYS CONNECTED.
     * */
    alwaysReconnect?: boolean
};

/** 
 * Connect to a ProtoV2d server over WebSocket. 
 * 
 * By default, `reconnectionTime` is 5s, this means that it will retry connection every 5s if the connection is closed; `timeout` is 10s.
 */
export function connect(config: ClientWSConfig & ClientReconnectConfig) {
    return connectWithCustomConnect(config, connectWebsocket);
}

/** 
 * Connect to a ProtoV2d server with your own protocol. This will handle reconnection for you.
 * 
 * By default, `reconnectionTime` is 5s, this means that it will retry connection every 5s if the connection is closed; `timeout` is 10s.
 */
export async function connectWithCustomConnect<CustomConfig, BackendData>(
    config: ClientCommonConfig & CustomConfig & ClientReconnectConfig,
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

            baseSession.wc!.once("close", async (explict, reason) => {
                log("connection closed, explict: %s, reason: %s", explict, reason);

                // do not reconnect if explictly closed
                if (explict && !config.alwaysReconnect) {
                    baseSession.emit("finalClose"); return;
                };

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
            if (r === (config.maxInitialRetries ?? Infinity) - 1) break;
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
        log("attempting to connect to ws server");
        ws.binaryType = "arraybuffer";

        // Client side cannot access real server IP.
        let wc = new WrappedConnection(null, ws);

        function handleError(err: WebSocket.ErrorEvent) {
            reject(err);

            if (!wc.closed) {
                wc.emit("close", false, err.message);
            }

            ws.removeEventListener("error", handleError);
            ws.removeEventListener("close", handleClose);
            ws.removeEventListener("message", handleData);
            wc.removeListener("tx", handleSendData);
        }

        function handleClose(e: WebSocket.CloseEvent) {
            reject(new Error(e.reason));

            if (!wc.closed) {
                wc.emit("close", false, e.reason);
            }

            ws.removeEventListener("error", handleError);
            ws.removeEventListener("close", handleClose);
            ws.removeEventListener("message", handleData);
            wc.removeListener("tx", handleSendData);
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

        async function handleSendData(data: Uint8Array) {
            if (ws.readyState !== ws.OPEN) {
                reject(new Error("connection is not open"));
                return;
            }

            ws.send(data);
        }

        ws.addEventListener("error", handleError);
        ws.addEventListener("close", handleClose);
        ws.addEventListener("message", handleData);
        await new Promise<void>(r => ws.addEventListener("open", () => r()));
        wc.on("tx", handleSendData);
        wc.once("close", (_explict: boolean, reason?: string) => {
            if (ws.readyState === ws.CLOSED || ws.readyState === ws.CLOSING) return;
            ws.close(1000, reason);
        });

        log("connected to ws server");

        try {
            resolve(connectWrapped({ ...config, wc }));
        } catch (e) {
            reject(e);
            ws.removeEventListener("error", handleError);
            ws.removeEventListener("close", handleClose);
            ws.removeEventListener("message", handleData);
            wc.removeListener("tx", handleSendData);
        }
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
        let pkValues: [isHash: boolean, value: Uint8Array][] = [];
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
            wc.removeListener("close", onCloseWC);
            wc.emit("close", true, "handshake failed");
            wc.removeListener("rx", onIncomingData);
        }

        function onCloseWC(_explict: boolean, reason?: string) {
            reject(new Error("Socket closed before handshake succeeded" + (reason ? ": " + reason : "")));
            wc.removeListener("rx", onIncomingData);
            wc.removeListener("close", onCloseWC);
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

                log(`negotiated version ${state.version}`);
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
                            log(`received handshake v1 packet ${state.currentPacket}`)

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

                                let signatureClassic = signature.slice(0, 64);
                                let signaturePQ = signature.slice(66); // 2-byte length?
                                let signaturePKClassic = signaturePK.slice(0, 32);
                                let signaturePKPQ = signaturePK.slice(32);

                                if (signature[64] !== 0xf3 || signature[65] !== 0x11) {
                                    rejectHandshake("Invalid signature"); return;
                                }

                                let verified1 = ed25519.verify(signatureClassic, pqPK, signaturePKClassic);
                                if (!verified1) {
                                    rejectHandshake("New public key classic signature verification failed"); return;
                                }

                                let verified2 = await dilithium5.verify(signaturePQ, pqPK, signaturePKPQ);
                                if (!verified2) {
                                    rejectHandshake("New public key PQ signature verification failed"); return;
                                }
                            }


                            let enc = await kyber.encapsulate(pqPK);

                            encryptionKeyPQ = await crypto.subtle.importKey("raw", enc.sharedSecret, "AES-GCM", false, ["encrypt", "decrypt"]);

                            state.currentPacket = 2;
                            wc.send(joinUint8Array([0x02], encode([3, Uint8ArrayToHex(enc.ciphertext)])));
                            break;
                        }

                        case 2: {
                            let packet = decode(await aesDecrypt(data.slice(1), encryptionKeyPQ!, false)) as [4, string];
                            if (packet[0] !== 4) {
                                rejectHandshake("Invalid packet"); return;
                            }
                            log(`received handshake v1 packet ${state.currentPacket}`);

                            // v1 server require signature of sha512(sha512(null) + sha512(random from server)).
                            let encoder = new TextEncoder();
                            let rndRaw = encoder.encode(packet[1]);
                            let rnd512 = new Uint8Array(await crypto.subtle.digest("SHA-512", rndRaw));
                            let rnd = new Uint8Array(await crypto.subtle.digest("SHA-512", joinUint8Array(SHA512_NULL, rnd512)));

                            let sessionKeyClassic = sessionKey.slice(0, 32);
                            let sessionKeyPQ = sessionKey.slice(64);

                            // `superdilithium`/dilithium5 implementation used in v1-capable servers uses the first 2 bytes to indicate the length of the signature (F311 = 4595 in little-endian).
                            // seriously what the fuck
                            // this wasted 2 hours of my life
                            let signature = Uint8ArrayToHex(ed25519.sign(rnd, sessionKeyClassic)) + "f311" + Uint8ArrayToHex((await dilithium5.sign(rnd, sessionKeyPQ)).signature);

                            state.currentPacket = 3;
                            wc.send(joinUint8Array([0x02], await aesEncrypt(encode([5, Uint8ArrayToHex(sessionID), signature]), encryptionKeyPQ!, false)));
                            break;
                        }

                        case 3: {
                            let packet = decode(await aesDecrypt(data.slice(1), encryptionKeyPQ!, false)) as [6, boolean];
                            if (packet[0] !== 6) {
                                rejectHandshake("Invalid packet"); return;
                            }
                            log(`received handshake v1 packet ${state.currentPacket}`);

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
                            wc.removeListener("close", onCloseWC);
                            break;
                        }
                    }
                    break;
                }

                case 2: {
                    switch (state.currentPacket) {
                        case 1: {
                            if (data[1] !== 0x02) {
                                rejectHandshake("Invalid packet"); return;
                            }
                            log(`received handshake v2 packet ${state.currentPacket}`);

                            switch (data[2]) {
                                case 0x01: {
                                    // Encryption enabled
                                    state.encryption = true;

                                    let exchangeClassic = data.slice(3, 35);
                                    let exchangePQ = data.slice(35, 1603);
                                    let exchangeFull = data.slice(3, 1603);
                                    let random = data.slice(6262, 6326);

                                    if (!noVerify) {
                                        let signatureClassic = data.slice(1603, 1667);
                                        let signaturePQ = data.slice(1667, 6262);

                                        let pk = data.slice(6326);
                                        let pkh = isFullKeyOnly ? pk : new Uint8Array(await crypto.subtle.digest("SHA-256", pk));

                                        let kc = await Promise.all(pkValues.map(async v => {
                                            if (v[0]) {
                                                // Public key hash
                                                return [pk, exactArray(v[1], pkh)] as const;
                                            } else {
                                                if (isFullKeyOnly) {
                                                    // Server will send hash only. Compute hash.
                                                    let vPKH = new Uint8Array(await crypto.subtle.digest("SHA-256", v[1]));

                                                    return [v[1], exactArray(vPKH, pkh)] as const;
                                                } else {
                                                    // Server will send full key.
                                                    return [v[1], exactArray(v[1], pk)] as const;
                                                }
                                            }
                                        }));

                                        let k = kc.find(x => x[1]);
                                        if (!k) {
                                            rejectHandshake("No public key matches"); return;
                                        }

                                        let classicPart = k[0].slice(0, 32);
                                        let pqPart = k[0].slice(32);

                                        let verified1 = ed25519.verify(signatureClassic, exchangeFull, classicPart);
                                        if (!verified1) {
                                            rejectHandshake("New public key classic signature verification failed", true); return;
                                        }

                                        let verified2 = await dilithium5.verify(signaturePQ, exchangeFull, pqPart);
                                        if (!verified2) {
                                            rejectHandshake("New public key PQ signature verification failed", true); return;
                                        }
                                    }

                                    let pqData = await kyber.encapsulate(exchangePQ);
                                    encryptionKeyPQ = await crypto.subtle.importKey("raw", pqData.sharedSecret, "AES-GCM", false, ["encrypt", "decrypt"]);

                                    let classicRandomPrivate = crypto.getRandomValues(new Uint8Array(32));
                                    let classicRandomPublic = x25519.getPublicKey(classicRandomPrivate);

                                    let classicKey = x25519.getSharedSecret(classicRandomPrivate, exchangeClassic);
                                    encryptionKeyClassic = await crypto.subtle.importKey("raw", classicKey, "AES-GCM", false, ["encrypt", "decrypt"]);

                                    let sessionSignatureClassic = ed25519.sign(random, sessionKey.slice(0, 32));
                                    let sessionSignaturePQ = (await dilithium5.sign(random, sessionKey.slice(64))).signature;

                                    log(`sending handshake v2 packet ${state.currentPacket}`);
                                    state.currentPacket = 2;
                                    wc.send(joinUint8Array(
                                        [0x02, 0x03],
                                        classicRandomPublic, pqData.ciphertext,
                                        await aesEncrypt(await aesEncrypt(joinUint8Array(sessionID, sessionSignatureClassic, sessionSignaturePQ), encryptionKeyPQ, true), encryptionKeyClassic, true)
                                    ));
                                    log(`signature length ${sessionID.length + sessionSignatureClassic.length + sessionSignaturePQ.length}`);
                                    break;
                                }

                                case 0x02: {
                                    // Encryption disabled
                                    state.encryption = false;

                                    if (!config.disableEncryption) {
                                        rejectHandshake("Server send non-encryption, but client does not disable encryption."); return;
                                    }

                                    let random = data.slice(3, 67);
                                    let sessionSignatureClassic = ed25519.sign(random, sessionKey.slice(0, 32));
                                    let sessionSignaturePQ = (await dilithium5.sign(random, sessionKey.slice(64))).signature;

                                    log(`sending handshake v2 packet ${state.currentPacket}`);
                                    state.currentPacket = 2;
                                    wc.send(joinUint8Array([0x02, 0x03], sessionID, sessionSignatureClassic, sessionSignaturePQ));
                                    log(`signature length ${sessionID.length + sessionSignatureClassic.length + sessionSignaturePQ.length}`);
                                    break;
                                }

                                case 0x03: {
                                    // Server does not allow non-encryption
                                    rejectHandshake("Server does not allow disabling encryption"); return;
                                }

                                case 0x04: {
                                    // Version mismatch
                                    rejectHandshake(`Server does not support client version (advertised: ${(decode(data.slice(3)) as number[]).join(", ")}; client supported: 2)`); return;
                                }

                                default: {
                                    rejectHandshake("Invalid packet"); return;
                                }
                            }
                            break;
                        }

                        case 2: {
                            if (data[1] !== 0x04) {
                                rejectHandshake("Invalid packet"); return;
                            }
                            log(`received handshake v2 packet ${state.currentPacket}`);

                            state.handshaked = true;
                            state.currentPacket = 3;

                            if (data[2]) {
                                log(`handshake done, resume failed`);
                                let newSession = new ProtoV2dSession(Uint8ArrayToHex(sessionID), 2, true, wc, [encryptionKeyPQ, encryptionKeyClassic].filter(filterNull), timeout);
                                if (sessionObject) {
                                    sessionObject.emit("resumeFailed", newSession);
                                    sessionObject.close();
                                }

                                sessionObject = newSession;
                            } else {
                                log(`handshake done, resume success`);
                                if (!sessionObject) {
                                    sessionObject = new ProtoV2dSession(Uint8ArrayToHex(sessionID), 2, true, wc, [encryptionKeyPQ, encryptionKeyClassic].filter(filterNull), timeout);
                                } else {
                                    sessionObject.protocolVersion = 2;
                                    sessionObject.encryption = [encryptionKeyPQ, encryptionKeyClassic].filter(filterNull);
                                    sessionObject.wc = wc;
                                    sessionObject.timeout = timeout;
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
            }
        }

        wc.on("rx", onIncomingData);
        wc.on("close", onCloseWC);

        if (config.handshakeV1 === "forced") {
            state.version = 1;
            state.currentPacket = 1;
            log("sending handshake v1");
            wc.send(joinUint8Array([0x02], encode([1, 1])));
        } else {
            state.version = config.handshakeV1 === "disabled" ? 2 : 0;
            state.currentPacket = 1;
            log("sending handshake v2");
            wc.send(joinUint8Array([0x02], encode([1, 2, [2], config.disableEncryption ? 2 : (isFullKeyOnly ? 0 : 1)])));
        }
    });
}
