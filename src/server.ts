import type { Server as HTTPServer, IncomingMessage } from "http";
import type { Server as HTTPSServer } from "https";

import ws from "ws";
import { EventEmitter } from "events";
import { Buffer } from "buffer";
import { encode, decode } from "msgpack-lite";
import ip from "ip-address";
import debug from "debug";

import { hexToUint8Array, Uint8ArrayToHex, randomString, proxyTrustResolver, aesDecrypt, joinUint8Array, filterNull } from "./utils.js";

import Kyber, { type KEM as KyberKEM } from "@dashlane/pqc-kem-kyber1024-browser";
import Dilithium5, { type SIGN as Dilithium5SIGN } from "@dashlane/pqc-sign-dilithium5-browser";
import { x25519, ed25519 } from "@noble/curves/ed25519";

import ProtoV2dSession from "./session.js";
import type { Duplex } from "stream";
import { WrappedConnection } from "./connection.js";

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
    trustProxy?: boolean | string[];
    allowDisableEncryption?: boolean;
    disableWASM?: boolean;
    wasmCustomPath?: {
        kyber1024?: string;
        dilithium5?: string;
    }
} & (
        { port: number } |
        { server: HTTPServer | HTTPSServer } |
        { wsServer: ws.Server } |
        {}
    )

export interface ProtoV2dServer extends EventEmitter {
    on(event: "connection", listener: (session: ProtoV2dSession) => void): this;
    on(event: "ready", listener: () => void): this;
    emit(event: "connection", session: ProtoV2dSession): boolean;
    emit(event: "ready"): boolean;
}

export class ProtoV2dServer extends EventEmitter {
    private debug = debug("protov2d:server");

    private wsServer: ws.Server;
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
            privateKey: fullPrivateKey.slice(32),
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

        this.kyber = Kyber(config.disableWASM);
        this.dilithium5 = Dilithium5(config.disableWASM);
    }

    public handleWSUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer) {
        if (!this.wsServer) throw new Error("Server not ready");

        this.wsServer.handleUpgrade(request, socket, head, (client) => {
            this.wsServer.emit("connection", client, request, this.wsServer);
        });
    }

    public handleWSConnection(client: ws.WebSocket, header: IncomingMessage) {
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

        let wrapped = new WrappedConnection(realIP, client);
        client.on("message", (data: ws.Data) => {
            let rawPacket: Uint8Array;

            if (typeof data === "string") {
                let textEncoder = new TextEncoder();
                rawPacket = textEncoder.encode(data);
            } else if (data instanceof ArrayBuffer) {
                rawPacket = new Uint8Array(data);
            } else if (data instanceof Buffer) {
                rawPacket = Uint8Array.from(data);
            } else {
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
    }

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

        let pingResponse = new Map<number, () => void>();

        let asymmKeyPQ: { privateKey: Uint8Array, publicKey: Uint8Array } | null = null;
        let asymmKeyClassic: { privateKey: Uint8Array, publicKey: Uint8Array } | null = null;
        let encryptionKeyPQ: CryptoKey | null = null;
        let encryptionKeyClassic: CryptoKey | null = null;

        let session: ProtoV2dSession | null = null;
        //#endregion

        let closeConnection = () => {
            wc.emit("close");
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
                        // Client supports version 1 ONLY
                        state.version = 1;
                        state.currentPacket = 1;

                        // Send handshake packet
                        // Version 1 only uses post-quantum encryption.
                        asymmKeyPQ = await (await this.kyber).keypair();

                        let { signature: signaturePQ } = await (await this.dilithium5).sign(asymmKeyPQ.publicKey, this.pqKeyPair.privateKey);
                        let signatureClassic = ed25519.sign(asymmKeyPQ.publicKey, this.classicKeyPair.privateKey);

                        let handshakePacket = encode([
                            2,
                            Uint8ArrayToHex(asymmKeyPQ.publicKey),
                            Uint8ArrayToHex(signatureClassic) + Uint8ArrayToHex(signaturePQ),
                            Uint8ArrayToHex(this.classicKeyPair.publicKey) + Uint8ArrayToHex(this.pqKeyPair.publicKey)
                        ]);

                        state.encryption = true;

                        wc.send(joinUint8Array([0x02], handshakePacket));
                    } else if (handshakePacket[1] === 2) {
                        // Handshake version 2
                        if (!handshakePacket[2].includes(2)) {
                            let mismatchedPacket = encode([2]);
                            wc.send(joinUint8Array([0x02, 0x02, 0x04], mismatchedPacket));
                            closeConnection();
                            return;
                        }

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

                            // Handshake without encryption (no signature needed)
                            wc.send(joinUint8Array([0x02, 0x02], state.challenge2));
                            state.encryption = false;
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
                            let signatureClassic = ed25519.sign(fullPublicKey, this.classicKeyPair.privateKey);

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
                        // TODO: Implement version 1
                        break;
                    }

                    case 2: {
                        if (!state.handshaked && rawPacket[0] !== 0x02) {
                            // Invalid state
                            closeConnection();
                        }

                        switch (state.currentPacket) {
                            case 1: {
                                if (rawPacket[1] !== 0x03) {
                                    // Invalid state
                                    closeConnection(); return;
                                }

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
                                    sigPart = rawPacket.slice(1);
                                }

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

                                // Create session
                                let sessionID = Uint8ArrayToHex(fullSessionPublic);
                                if (this.sessions.has(sessionID) && !this.sessions.get(sessionID)!.closed) {
                                    // Session already exists, resume
                                    wc.send([0x04, 0x00]);

                                    session = this.sessions.get(sessionID)!;
                                    session.clientSide = false;
                                    session.protocolVersion = 2;
                                    session.wc = wc;
                                    session.encryption = [encryptionKeyPQ, encryptionKeyClassic].filter(filterNull);
                                } else {
                                    // Session doesn't exist, create new
                                    wc.send([0x04, 0x01]);

                                    session = new ProtoV2dSession(sessionID, 2, false, wc, [encryptionKeyPQ, encryptionKeyClassic].filter(filterNull));
                                    this.sessions.set(sessionID, session);

                                    this.emit("connection", session);
                                }
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
}
