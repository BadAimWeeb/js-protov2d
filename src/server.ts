import type { Server as HTTPServer, IncomingMessage } from "http";
import type { Server as HTTPSServer } from "https";

import ws from "ws";
import { EventEmitter } from "events";
import { Buffer } from "buffer";
import { encode, decode } from "msgpack-lite";
import ip from "ip-address";
import debug from "debug";

import { hexToUint8Array, Uint8ArrayToHex, randomString, proxyTrustResolver, aesDecrypt, joinUint8Array, filterNull, aesEncrypt, SHA512_NULL } from "./utils.js";

import { type KEM as KyberKEM } from "@dashlane/pqc-kem-kyber1024-browser";
import { type SIGN as Dilithium5SIGN } from "@dashlane/pqc-sign-dilithium5-browser";
import { x25519, ed25519 } from "@noble/curves/ed25519";

import ProtoV2dSession from "./session.js";
import type { Duplex } from "stream";
import { WrappedConnection } from "./connection.js";
import { getDilithium5, getKyber } from "./pqcache.js";

/**
 * This config allows you to choose 4 modes of upgrading connections:
 * 1. Using a port number
 * 2. Using an existing HTTP(S) server
 * 3. Passing no config, which indicates that you'll handle connection yourself and pass it here to upgrade.
 * 4. Passing a WS server.
 * 
 * In all cases, you need to provide a private key and a public key.
 * 
 * If you are behind a proxy (either local reverse proxy or cloudflare), you can set `trustProxy` to true or an array of trusted proxies CIDR.
 * 
 * For debugging purposes, you may enable `allowDisableEncryption` to allow clients to disable encryption.
 * 
 * In case you want to explictly disable WASM, you may set `disableWASM` to `true`. JS fallback will be used instead.
 */
export type ServerConfig = {
    privateKey: string | Uint8Array;
    publicKey: string | Uint8Array;
    streamTimeout?: number;
    pingTimeout?: number;
    trustProxy?: boolean | string[];
    allowDisableEncryption?: boolean;
    disableWASM?: boolean;
} & (
        { port: number } |
        { server: HTTPServer | HTTPSServer } |
        { wsServer: ws.Server } |
        {}
    )

export interface ProtoV2dServer extends EventEmitter {
    /** This event will return session from clients. */
    on(event: "connection", listener: (session: ProtoV2dSession) => void): this;
    emit(event: "connection", session: ProtoV2dSession): boolean;

    /** Dead/timed out session will be emitted here. */
    on(event: "dropConnection", listener: (session: ProtoV2dSession) => void): this;
    emit(event: "dropConnection", session: ProtoV2dSession): boolean;
}

export class ProtoV2dServer extends EventEmitter {
    private debug = debug("protov2d:server");

    public wsServer: ws.Server;
    private sessions: Map<string, ProtoV2dSession> = new Map();
    private trustProxy: boolean | (ip.Address4 | ip.Address6)[];

    private kyber: Promise<KyberKEM>;
    private dilithium5: Promise<Dilithium5SIGN>;

    private pqKeyPair: { privateKey: Uint8Array, publicKey: Uint8Array };
    private classicKeyPair: { privateKey: Uint8Array, publicKey: Uint8Array };
    private publicKeyHash: Promise<Uint8Array>;

    /**
     * You may see {@link ServerConfig} for more information on how to config this.
     */
    constructor(private config: ServerConfig) {
        super();

        if (!("privateKey" in config)) throw new Error("No private key provided");
        if (!("publicKey" in config)) throw new Error("No public key provided");

        let fullPrivateKey: Uint8Array;
        let fullPublicKey: Uint8Array;
        if (typeof config.privateKey === "string") {
            fullPrivateKey = hexToUint8Array(config.privateKey);
        } else {
            fullPrivateKey = config.privateKey;
        }

        if (typeof config.publicKey === "string") {
            fullPublicKey = hexToUint8Array(config.publicKey);
        } else {
            fullPublicKey = config.publicKey;
        }

        this.classicKeyPair = {
            privateKey: fullPrivateKey.slice(0, 32),
            publicKey: fullPublicKey.slice(0, 32)
        };

        this.pqKeyPair = {
            privateKey: fullPrivateKey.slice(64),
            publicKey: fullPublicKey.slice(32)
        };

        this.publicKeyHash = (async () => {
            let hash = await crypto.subtle.digest("SHA-256", fullPublicKey);
            return new Uint8Array(hash);
        })();

        if ("trustProxy" in config) {
            if (Array.isArray(config.trustProxy)) {
                this.trustProxy = config.trustProxy.map(x => {
                    try {
                        return new ip.Address6(x);
                    } catch {
                        return new ip.Address4(x);
                    }
                });
            } else {
                this.trustProxy = !!config.trustProxy;
            }
        } else {
            this.trustProxy = false;
        }

        if ("server" in config) {
            this.wsServer = new ws.Server({ server: config.server });
        } else if ("port" in config) {
            this.wsServer = new ws.Server({ port: config.port });
        } else if ("wsServer" in config) {
            this.wsServer = config.wsServer;
        } else {
            this.wsServer = new ws.Server({ noServer: true });
        }

        this.wsServer.on("connection", this.handleWSConnection.bind(this));

        this.kyber = getKyber(!!config.disableWASM);
        this.dilithium5 = getDilithium5(!!config.disableWASM);
    }

    /** Pass upgrade request from HTTP here. */
    public handleWSUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer) {
        if (!this.wsServer) throw new Error("Server not ready");

        this.wsServer.handleUpgrade(request, socket, head, (client) => {
            this.wsServer.emit("connection", client, request, this.wsServer);
        });
    }

    /** Pass existing WebSocket connection here. */
    public handleWSConnection(client: ws.WebSocket, header: IncomingMessage) {
        client.binaryType = "arraybuffer";

        let realIP: ip.Address4 | ip.Address6 | null = null;
        let chainIP: string[] = [];

        // Read X-Forwarded-For header
        let xFF = header.headers["x-forwarded-for"];
        if (xFF) {
            if (typeof xFF === "string") {
                chainIP.push(...xFF.split(",").map(x => x.trim()));
            } else if (Array.isArray(xFF)) {
                chainIP.push(...xFF.map(x => x.split(",").map(y => y.trim())).flat());
            }
        }
        chainIP.push(header.socket.remoteAddress!);

        // Trust proxy
        realIP = proxyTrustResolver(chainIP, this.trustProxy);

        this.debug("incoming connection from %s", realIP?.address ?? "unknown");

        let wrapped = new WrappedConnection(realIP, client);
        client.on("message", (data: ws.Data) => {
            let rawPacket: Uint8Array;

            if (typeof data === "string") {
                let textEncoder = new TextEncoder();
                rawPacket = textEncoder.encode(data);
            } else if (data instanceof ArrayBuffer) {
                rawPacket = new Uint8Array(data);
            } else if (data instanceof Buffer) { // these are redundant but just in case
                rawPacket = Uint8Array.from(data);
            } else { // these are redundant but just in case
                // Fragments
                rawPacket = data.map(x => Uint8Array.from(x)).reduce((a, b) => {
                    let c = new Uint8Array(a.length + b.length);
                    c.set(a);
                    c.set(b, a.length);
                    return c;
                });
            }

            wrapped.emit("rx", rawPacket);
        });

        wrapped.on("tx", (data) => {
            client.send(data);
        });

        wrapped.on("close", () => {
            client.close();
            client.removeAllListeners();
        });

        this.handleWrappedConnection(wrapped);
    }

    /** If you're using a custom protocol, receive data from proxy, etc..., construct WrappedConnection and pass data to "rx", send data from "tx". After that, put that object here. */
    public handleWrappedConnection(wc: WrappedConnection) {
        //#region State variables
        let state = {
            version: 0,
            currentPacket: 0,
            encryption: false,
            challenge1: "",
            challenge2: [] as number[],
            handshaked: false
        };

        let asymmKeyPQ: { privateKey: Uint8Array, publicKey: Uint8Array } | null = null;
        let asymmKeyClassic: { privateKey: Uint8Array, publicKey: Uint8Array } | null = null;
        let encryptionKeyPQ: CryptoKey | null = null;
        let encryptionKeyClassic: CryptoKey | null = null;

        let session: ProtoV2dSession | null = null;
        //#endregion

        let closeConnection = (reason?: string) => {
            wc.emit("close", true, reason);
            wc.removeListener("rx", handleIncomingPacket);
        }

        // Handle connection
        let handleIncomingPacket = async (rawPacket: Uint8Array) => {
            try {
                if (state.currentPacket === 0) {
                    // Handle initial handshake (no version known)
                    if (rawPacket[0] !== 0x02) {
                        closeConnection();
                        return;
                    }

                    let handshakePacket = decode(rawPacket.slice(1)) as [handshakePacketType: number, handshakeVersion: number, clientSupportedVersion: number[], encryptionVerifyMode: number];
                    if (handshakePacket[0] !== 1) {
                        closeConnection();
                        return;
                    }

                    if (handshakePacket[1] === 1) {
                        this.debug(`received client handshake v1 initial packet`);

                        // Client supports version 1 ONLY
                        state.version = 1;
                        state.currentPacket = 1;

                        // Send handshake packet
                        // Version 1 only uses post-quantum encryption.
                        asymmKeyPQ = await (await this.kyber).keypair();

                        let { signature: signaturePQ } = await (await this.dilithium5).sign(asymmKeyPQ.publicKey, this.pqKeyPair.privateKey);
                        let signatureClassic = ed25519.sign(asymmKeyPQ.publicKey, this.classicKeyPair.privateKey.slice(0, 32));

                        let handshakePacket = encode([
                            2,
                            Uint8ArrayToHex(asymmKeyPQ.publicKey),
                            // `superdilithium`/dilithium5 implementation used in v1-capable servers uses the first 2 bytes to indicate the length of the signature (F311 = 4595 in little-endian).
                            // seriously what the fuck
                            // this wasted 2 hours of my life
                            Uint8ArrayToHex(signatureClassic) + "f311" + Uint8ArrayToHex(signaturePQ),
                            Uint8ArrayToHex(this.classicKeyPair.publicKey) + Uint8ArrayToHex(this.pqKeyPair.publicKey)
                        ]);

                        state.encryption = true;

                        wc.send(joinUint8Array([0x02], handshakePacket));
                        return;
                    } else if (handshakePacket[1] === 2) {
                        // Handshake version 2
                        if (!handshakePacket[2].includes(2)) {
                            let mismatchedPacket = encode([2]);
                            wc.send(joinUint8Array([0x02, 0x02, 0x04], mismatchedPacket));
                            closeConnection();
                            return;
                        }

                        this.debug(`received client handshake v2 initial packet`);

                        // Client supports version 2
                        state.version = 2;
                        state.currentPacket = 1;

                        state.challenge2 = Array.from(crypto.getRandomValues(new Uint8Array(64)));
                        if (handshakePacket[3] === 2) {
                            // Disallow disabling encryption if configured
                            if (!this.config.allowDisableEncryption) {
                                wc.send([0x02, 0x02, 0x03]);
                                closeConnection();
                                return;
                            }

                            state.encryption = false;

                            // Handshake without encryption (no signature needed)
                            this.debug(`sending handshake v2 packet ${state.currentPacket}`);
                            wc.send(joinUint8Array([0x02, 0x02, 0x02], state.challenge2));

                        } else if (handshakePacket[3] === 0 || handshakePacket[3] === 1) {
                            // Handshake with encryption
                            state.encryption = true;

                            asymmKeyPQ = await (await this.kyber).keypair();
                            let priv25519 = crypto.getRandomValues(new Uint8Array(32));
                            asymmKeyClassic = {
                                privateKey: priv25519,
                                publicKey: x25519.getPublicKey(priv25519)
                            }

                            let fullPublicKey = new Uint8Array(asymmKeyClassic.publicKey.length + asymmKeyPQ.publicKey.length);
                            fullPublicKey.set(asymmKeyClassic.publicKey);
                            fullPublicKey.set(asymmKeyPQ.publicKey, asymmKeyClassic.publicKey.length);

                            let { signature: signaturePQ } = await (await this.dilithium5).sign(fullPublicKey, this.pqKeyPair.privateKey);
                            let signatureClassic = ed25519.sign(fullPublicKey, this.classicKeyPair.privateKey.slice(0, 32));

                            this.debug(`sending handshake v2 packet ${state.currentPacket}`);
                            wc.send(joinUint8Array(
                                [0x02, 0x02, 0x01],
                                fullPublicKey,
                                signatureClassic,
                                signaturePQ,
                                state.challenge2,
                                ...(handshakePacket[3] === 1 ? [this.classicKeyPair.publicKey, this.pqKeyPair.publicKey] : [await this.publicKeyHash])
                            ));
                        } else {
                            // Invalid state
                            closeConnection();
                        }
                        return;
                    } else {
                        // Server does not support this handshake version
                        let mismatchedPacket = encode([2]);
                        wc.send(joinUint8Array([0x02, 0x02, 0x04], mismatchedPacket));
                        closeConnection();
                        return;
                    }
                }

                switch (state.version) {
                    case 1: {
                        if (!state.handshaked && rawPacket[0] !== 0x02) {
                            // Invalid state
                            closeConnection(); return;
                        }

                        switch (state.currentPacket) {
                            case 1: {
                                let enc = decode(rawPacket.slice(1)) as [3, string];
                                if (enc[0] !== 3) {
                                    // Invalid state
                                    closeConnection(); return;
                                }
                                this.debug(`received handshake v1 packet ${state.currentPacket}`);
                                let cK = hexToUint8Array(enc[1]);

                                let sharedSecret = await (await this.kyber).decapsulate(cK, asymmKeyPQ!.privateKey);
                                encryptionKeyPQ = await crypto.subtle.importKey(
                                    "raw",
                                    sharedSecret.sharedSecret,
                                    "AES-GCM",
                                    true,
                                    ["encrypt", "decrypt"]
                                );

                                state.challenge1 = randomString(64);
                                let packet = encode([4, state.challenge1]);

                                state.currentPacket = 2;

                                let encryptedPacket = await aesEncrypt(packet, encryptionKeyPQ, false);
                                wc.send(joinUint8Array([0x02], encryptedPacket));
                                return;
                            }

                            case 2: {
                                let enc = decode(await aesDecrypt(rawPacket.slice(1), encryptionKeyPQ!, false)) as [5, string, string];
                                if (enc[0] !== 5) {
                                    // Invalid state
                                    closeConnection(); return;
                                }
                                this.debug(`received handshake v1 packet ${state.currentPacket}`);

                                // Verify session
                                let sessionKey = hexToUint8Array(enc[1]);
                                let signature = hexToUint8Array(enc[2]);

                                let sessionClassic = sessionKey.slice(0, 32);
                                let sessionPQ = sessionKey.slice(32);
                                let signatureClassic = signature.slice(0, 64);
                                let signaturePQ = signature.slice(66);

                                if (signature[64] !== 0xF3 || signature[65] !== 0x11) {
                                    this.debug("invalid post-quantum magic number signature for session");
                                    closeConnection(); 
                                    return;
                                }

                                // v1 server uses signature of sha512(sha512(null) + sha512(random from server)).
                                let utf8 = new TextEncoder();
                                let randomRaw = utf8.encode(state.challenge1);
                                let random512 = new Uint8Array(await crypto.subtle.digest("SHA-512", randomRaw));
                                let random = new Uint8Array(await crypto.subtle.digest("SHA-512", joinUint8Array(SHA512_NULL, random512)));

                                let verifiedClassic = ed25519.verify(signatureClassic, random, sessionClassic);
                                if (!verifiedClassic) {
                                    this.debug("invalid classic signature for session");
                                    closeConnection();
                                    return;
                                }

                                let verifiedPQ = await (await this.dilithium5).verify(signaturePQ, random, sessionPQ);
                                if (!verifiedPQ) {
                                    this.debug("invalid post-quantum signature for session");
                                    closeConnection();
                                    return;
                                }

                                // Passed signature verification
                                state.currentPacket = 3;
                                state.handshaked = true;

                                // Create session
                                let sessionID = Uint8ArrayToHex(sessionKey);
                                if (this.sessions.has(sessionID) && !this.sessions.get(sessionID)!.closed) {
                                    // Session already exists, resume
                                    let encryptedPacket = await aesEncrypt(encode([6, false]), encryptionKeyPQ!, false);
                                    wc.send(joinUint8Array([0x02], encryptedPacket));

                                    session = this.sessions.get(sessionID)!;
                                    session.clientSide = false;
                                    session.protocolVersion = 1;
                                    session.wc = wc;
                                    session.encryption = [encryptionKeyPQ!];

                                    this.debug("successfully resumed session");
                                } else {
                                    // Session doesn't exist, create new
                                    let encryptedPacket = await aesEncrypt(encode([6, true]), encryptionKeyPQ!, false);
                                    wc.send(joinUint8Array([0x02], encryptedPacket));

                                    session = new ProtoV2dSession(sessionID, 1, false, wc, [encryptionKeyPQ!], this.config.pingTimeout || 10000);
                                    this.sessions.set(sessionID, session);

                                    // session lifecycle management
                                    this._handleSessionLifecycle(session);

                                    this.emit("connection", session);

                                    this.debug("successfully created new session");
                                }

                                // handshaked done, drop handshake handler.
                                wc.removeListener("rx", handleIncomingPacket);

                                return;
                            }
                        }
                        break;
                    }

                    case 2: {
                        if (!state.handshaked && rawPacket[0] !== 0x02) {
                            // Invalid state
                            closeConnection(); return;
                        }

                        switch (state.currentPacket) {
                            case 1: {
                                if (rawPacket[1] !== 0x03) {
                                    // Invalid state
                                    closeConnection(); return;
                                }
                                this.debug(`received handshake v2 packet ${state.currentPacket}`);

                                let sigPart: Uint8Array;
                                if (state.encryption) {
                                    // Receive client's public key
                                    let clientKEXClassic = rawPacket.slice(2, 34);
                                    let clientKEXPQ = rawPacket.slice(34, 1602);

                                    // DH for X25519
                                    let sharedSecretClassic = x25519.getSharedSecret(asymmKeyClassic!.privateKey, clientKEXClassic);
                                    let sharedSecretPQ: Uint8Array;
                                    // Kyber stuff
                                    try {
                                        ({ sharedSecret: sharedSecretPQ } = await (await this.kyber).decapsulate(clientKEXPQ, asymmKeyPQ!.privateKey));
                                    } catch {
                                        // Invalid key exchange
                                        this.debug("invalid post-quantum key exchange");
                                        closeConnection();
                                        return;
                                    }

                                    // Convert to CryptoKey
                                    encryptionKeyClassic = await crypto.subtle.importKey(
                                        "raw",
                                        sharedSecretClassic,
                                        "AES-GCM",
                                        true,
                                        ["encrypt", "decrypt"]
                                    );

                                    encryptionKeyPQ = await crypto.subtle.importKey(
                                        "raw",
                                        sharedSecretPQ,
                                        "AES-GCM",
                                        true,
                                        ["encrypt", "decrypt"]
                                    );

                                    let sigPartRaw = rawPacket.slice(1602);
                                    sigPart = await aesDecrypt(await aesDecrypt(sigPartRaw, encryptionKeyClassic, true), encryptionKeyPQ, true);
                                } else {
                                    sigPart = rawPacket.slice(2);
                                }

                                this.debug(`signature length ${sigPart.length}, encryption: ${state.encryption}`);

                                // Verify signature
                                let sessionClassic = sigPart.slice(0, 32);
                                let sessionPQ = sigPart.slice(32, 2624);
                                let signatureClassic = sigPart.slice(2624, 2688);
                                let signaturePQ = sigPart.slice(2688);

                                let fullSessionPublic = sigPart.slice(0, 2624);
                                let verifiedClassic = ed25519.verify(signatureClassic, Uint8Array.from(state.challenge2), sessionClassic);
                                if (!verifiedClassic) {
                                    this.debug("invalid classic signature for session");
                                    closeConnection();
                                    return;
                                }

                                let verifiedPQ = await (await this.dilithium5).verify(signaturePQ, Uint8Array.from(state.challenge2), sessionPQ);
                                if (!verifiedPQ) {
                                    this.debug("invalid post-quantum signature for session");
                                    closeConnection();
                                    return;
                                }

                                // Passed signature verification
                                state.currentPacket = 2;
                                state.handshaked = true;

                                this.debug("successfully handshaked");

                                // Create session
                                let sessionID = Uint8ArrayToHex(fullSessionPublic);
                                if (this.sessions.has(sessionID) && !this.sessions.get(sessionID)!.closed) {
                                    this.debug("resuming");

                                    // Session already exists, resume
                                    wc.send([0x02, 0x04, 0x00]);

                                    session = this.sessions.get(sessionID)!;
                                    session.clientSide = false;
                                    session.protocolVersion = 2;
                                    session.wc = wc;
                                    session.encryption = [encryptionKeyPQ, encryptionKeyClassic].filter(filterNull);
                                    session.timeout = this.config.pingTimeout || 10000;
                                } else {
                                    this.debug("creating new session");
                                    // Session doesn't exist, create new
                                    wc.send([0x02, 0x04, 0x01]);

                                    session = new ProtoV2dSession(sessionID, 2, false, wc, [encryptionKeyPQ, encryptionKeyClassic].filter(filterNull), this.config.pingTimeout || 10000);
                                    this.sessions.set(sessionID, session);

                                    // session lifecycle management
                                    this._handleSessionLifecycle(session);

                                    this.emit("connection", session);
                                }

                                // handshaked done, drop handshake handler.
                                wc.removeListener("rx", handleIncomingPacket);
                            }
                        }
                        break;
                    }
                }
            } catch (e) {
                this.debug("error while handling connection: %O", e);
            }
        }

        wc.on("rx", handleIncomingPacket);
    }

    private _handleSessionLifecycle(session: ProtoV2dSession) {
        if (this.config.streamTimeout) {
            let timeout: ReturnType<typeof setTimeout>;
            let reconnectHandler = () => {
                clearTimeout(timeout);
            }

            let disconnectHandler = () => {
                timeout = setTimeout(() => {
                    session.close();
                    session.removeListener("connected", reconnectHandler);
                    session.removeListener("disconnected", disconnectHandler);
                    this.emit("dropConnection", session);
                    this.sessions.delete(session.connectionPK);
                }, this.config.streamTimeout!);

                session.once("connected", reconnectHandler);
            }

            session.on("disconnected", disconnectHandler);
        }
    }
}
