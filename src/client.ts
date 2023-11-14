import WebSocket from "isomorphic-ws";

import { encode, decode } from "msgpack-lite";
import { WrappedConnection } from "./connection.js";
import ProtoV2dSession from "./session.js";
import { Buffer } from "buffer";
import { hexToUint8Array, joinUint8Array } from "./utils.js";
import { keyGeneration } from "./keygen.js";

export type ClientCommonConfig = {
    timeout?: number,
    publicKey: {
        type: "key",
        value: string | Uint8Array
    } | {
        type: "hash",
        value: string | Uint8Array
    } | {
        type: "noverify"
    },
    disableEncryption?: boolean,
    existingData?: {
        sessionKey?: Uint8Array
    } & ({
        sessionID?: Uint8Array
    } | {
        sessionObject?: ProtoV2dSession
    }),
    handshakeV1?: "disabled" | "forced" | "auto"
}

export type ClientWSConfig = ClientCommonConfig & { url: string };
export type ClientWCConfig = ClientCommonConfig & { wc: WrappedConnection };

/** 
 * Connect to a ProtoV2d server over WebSocket. 
 * 
 * By default, `reconnectionTime` is 5s, this means that it will retry connection every 5s if the connection is closed; `timeout` is 10s.
 */
export function connect(config: ClientWSConfig & { reconnectionTime?: number }) {
    return connectWithCustomConnect(config, connectWebsocket);
}

/** 
 * Connect to a ProtoV2d server with your own protocol. This will handle reconnection for you.
 * 
 * By default, `reconnectionTime` is 5s, this means that it will retry connection every 5s if the connection is closed; `timeout` is 10s.
 */
export async function connectWithCustomConnect<CustomConfig, BackendData>(
    config: ClientCommonConfig & CustomConfig & { reconnectionTime?: number }, 
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

    for (; ;) {
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
        } catch {
            await new Promise<void>(r => setTimeout(r, config.reconnectionTime || 5000));
        }
    }
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
export function connectWrapped(config: ClientWCConfig) {

}
