import EventEmitter from "events";
import { Address4, Address6 } from "ip-address";

export interface WrappedConnection<BackendData> extends EventEmitter {
    /** Transmitting side of connection, you may hook to this and forward to your own protocol. */
    on(event: "tx", listener: (data: Uint8Array) => void): this;
    /** Send data. For internal/debugging only. */
    emit(event: "tx", data: Uint8Array): boolean;

    /** Receiving side of connection. For internal/debugging only. */
    on(event: "rx", listener: (data: Uint8Array) => void): this;
    /** Emit data from your own protocol to be handled. */
    emit(event: "rx", data: Uint8Array): boolean;

    /** Connection is closed. */
    on(event: "close", listener: () => void): this;
    /** Close connection. */
    emit(event: "close"): boolean;
}

export class WrappedConnection<BackendData = any> extends EventEmitter {
    closed = false;

    constructor(public realIP: Address4 | Address6 | null = null, public backendData: BackendData | null = null) {
        super();
        this.on("close", () => closed = true);
    }

    send(data: number[] | Uint8Array) {
        return this.emit("tx", data instanceof Uint8Array ? data : Uint8Array.from(data));
    }
}
