import { EventEmitter } from "events";

export default interface ProtoV2dSession extends EventEmitter {
    /** Use this to receive data */
    on(event: "data", listener: (QoS: 0 | 1, data: Uint8Array) => void): this;
    emit(event: "data", QoS: 0 | 1, data: Uint8Array): boolean;

    /** For debug purposes only: Also captures data that will send to other side */
    on(event: "data_ret", listener: (QoS: 0 | 1, data: Uint8Array, dupID?: number) => void): this;
    emit(event: "data_ret", QoS: 0 | 1, data: Uint8Array, dupID?: number): boolean;

    /** Notification channel for when a QoS 1 packet is queued for redelivery */
    on(event: "qos1:queued", listener: (dupID: number) => void): this;
    emit(event: "qos1:queued", dupID: number): boolean;

    /** Close */
    on(event: "closed", listener: () => void): this;
    emit(event: "closed"): boolean;

    on(event: "close_this", listener: () => void): this;
    emit(event: "close_this"): boolean;

    /** Signal */
    on(event: "disconnected", listener: () => void): this;
    emit(event: "disconnected"): boolean;

    on(event: "connected", listener: () => void): this;
    emit(event: "connected"): boolean;

    on(event: "resumeFailed", listener: (newStream: ProtoV2dSession) => void): this;
    emit(event: "resumeFailed", newStream: ProtoV2dSession): boolean;
}

type ConditionalSend<T extends (0 | 1)> = T extends 1 ? Promise<void> : T extends 0 ? void : never;

export default class ProtoV2dSession extends EventEmitter {
    closed = false;

    get connected() {
        return this.listenerCount("data_ret")
    }

    isClientSide: boolean;

    connectionPK: string;
    qos1Buffer: [dupID: number, data: Uint8Array][] = [];
    qos1Accepted: Set<number> = new Set();
    qos1ACKCallback: Map<number, () => void> = new Map();
    qos1Counter: number = 0;

    constructor(connectionPK: string, clientSide: boolean) {
        super();
        this.connectionPK = connectionPK;
        this.isClientSide = clientSide;
    }

    /** Send data to other side */
    send<T extends (0 | 1)>(QoS: T, data: Uint8Array): ConditionalSend<T> {
        if (QoS === 1) {
            let dupID = (this.qos1Counter++ << 1) | (this.isClientSide ? 0 : 1);
            let isListening = this.emit("data_ret", QoS, data, dupID);

            if (!isListening) {
                return new Promise<void>((resolve) => {
                    this.qos1Buffer.push([dupID, data]);
                    this.emit("qos1:queued", dupID);
                    this.qos1ACKCallback.set(dupID, resolve);
                }) as ConditionalSend<T>;
            } else {
                return new Promise<void>((resolve) => {
                    this.qos1ACKCallback.set(dupID, resolve);
                }) as ConditionalSend<T>;
            }
        } else {
            this.emit("data_ret", QoS, data);
        }
    }

    close() {
        this.closed = true;
        this.emit("closed");
        this.emit("close_this");
    }
}