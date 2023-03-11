import { WebSocket } from "isomorphic-ws";

import { Buffer } from "buffer";
import { encode, decode } from "msgpack-lite";

import pkg1 from "kyber-crystals";
import pkg2 from "superdilithium";
const { kyber } = pkg1;
const { superDilithium } = pkg2;

import { randomString } from "./utils.js";

const SubtleCrypto = crypto.subtle;

import ProtoV2dSession from "./session.js";

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

export async function connect(config: ClientConfig, reconnectionData?: {
    sessionKey: Uint8Array,
    sessionID: Uint8Array,
    sessionInstance: ProtoV2dSession
}) {
    let ws = new WebSocket(config.url);

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

    ws.send([0x02].concat(encode()));

    ws.on("message", async data => {
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


        } catch { }
    });
}