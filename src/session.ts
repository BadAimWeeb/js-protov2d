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
    on(event: "close", listener: () => void): this;
    emit(event: "close"): boolean;
}

export default class ProtoV2dSession extends EventEmitter {
    isClientSide: boolean;

    connectionID: string;
    qos1Buffer: [dupID: number, data: Uint8Array][] = [];
    qos1Accepted: Set<number> = new Set();
    qos1Counter: number = 0;

    constructor(connectionID: string, clientSide: boolean) {
        super();
        this.connectionID = connectionID;
        this.isClientSide = clientSide;
    }

    /** Send data to other side */
    send(QoS: 0 | 1, data: Uint8Array): void {
        if (QoS === 1) {
            let dupID = (this.qos1Counter++ << 1) | (this.isClientSide ? 0 : 1);
            this.emit("data_ret", QoS, data, dupID);
        } else {
            this.emit("data_ret", QoS, data);
        }
    }
}