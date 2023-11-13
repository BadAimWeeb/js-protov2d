import { EventEmitter } from "events";
import { WrappedConnection } from "./connection";
import { joinUint8Array } from "./utils";

export default interface ProtoV2dSession extends EventEmitter {
    /** Use this to receive data */
    on(event: "data", listener: (QoS: 0 | 1, data: Uint8Array) => void): this;
    emit(event: "data", QoS: 0 | 1, data: Uint8Array): boolean;

    /** For internal purposes only: Also captures raw packet that will send to other side */
    on(event: "data_ret", listener: (data: Uint8Array) => void): this;
    emit(event: "data_ret", data: Uint8Array): boolean;

    /** Close */
    on(event: "closed", listener: () => void): this;
    emit(event: "closed"): boolean;

    /* Signal */
    on(event: "disconnected", listener: () => void): this;
    emit(event: "disconnected"): boolean;

    on(event: "connected", listener: () => void): this;
    emit(event: "connected"): boolean;

    on(event: "resumeFailed", listener: (newStream: ProtoV2dSession) => void): this;
    emit(event: "resumeFailed", newStream: ProtoV2dSession): boolean;

    on(event: "wcChanged", listener: (oldWC: WrappedConnection, newWC: WrappedConnection) => void): this;
    emit(event: "wcChanged", oldWC: WrappedConnection | null, newWC: WrappedConnection | null): boolean;
}

type ConditionalSend<T extends (0 | 1)> = T extends 1 ? Promise<void> : T extends 0 ? undefined : never;

export default class ProtoV2dSession extends EventEmitter {
    closed = false;

    get connected() {
        return !(this.wc || {closed: true}).closed;
    }

    //qos1Buffer: [dupID: number, data: Uint8Array][] = [];
    qos1Buffer = new Map<number, Uint8Array | true>();
    qos1Wait = new Set<number>();
    qos1ACKCallback = new Map<number, () => void>();
    qos1Counter: number = 0;

    private _wc: WrappedConnection | null;
    get wc() {
        return this._wc;
    }

    set wc(wc: WrappedConnection | null) {
        if (this._wc) this._handleOldWC(this._wc);
        this.emit("wcChanged", this._wc, wc);
        this._wc = wc;
        if (wc) this._handleWC(wc);
    }

    private _ping = Infinity;
    get ping() {
        return this._ping;
    }

    private _encryption: CryptoKey[];
    set encryption(key: CryptoKey[]) {
        this._encryption = key;
    }

    constructor(public connectionPK: string, public protocolVersion: number, public clientSide: boolean, wc: WrappedConnection, encryption: CryptoKey[]) {
        super();
        this._wc = wc;
        this._encryption = encryption;
        this._handleWC(wc);
    }

    private _handleWC(wc: WrappedConnection) {
        wc.on("rx", this._bindHandleIncomingWCMessage);
        wc.on("close", this._bindHandleWCCloseEvent);
    }

    private _handleOldWC(wc: WrappedConnection) {
        wc.removeListener("rx", this._bindHandleIncomingWCMessage);
        wc.removeListener("close", this._bindHandleWCCloseEvent);
    }

    //#region Event stuff
    private _handleIncomingWCMessage(data: Uint8Array) {

    }
    private _bindHandleIncomingWCMessage = this._handleIncomingWCMessage.bind(this);

    private _handleWCCloseEvent() {
        this.emit("disconnected");
        this.wc!.removeListener("close", this._bindHandleWCCloseEvent);
    }
    private _bindHandleWCCloseEvent = this._handleWCCloseEvent.bind(this);
    //#endregion

    /** Destroy object without destroying WC. All listener will be removed to make this object GC-able. WC pointer will also be null. */
    public destroy() {
        this._wc = null;
        if (!this.closed) this.emit("closed");
        this.closed = true;
        this.removeAllListeners();
    }

    /** Close connection and destory object. All listener will be removed to make this object GC-able. WC pointer will also be null. */
    public close() {
        if (!this.closed) this.emit("closed");
        this.closed = true;
        this.wc?.emit("close");
        this._wc = null;
        this.removeAllListeners();
    }

    /** Send data to other side */
    public send<T extends (0 | 1)>(QoS: T, data: Uint8Array, overrideDupID?: number): ConditionalSend<T> {
        if (QoS === 1) {
            if (!this.wc) return Promise.reject(new Error("No connection")) as ConditionalSend<T>;

            let dupID = overrideDupID ?? ((this.qos1Counter++ << 1) | (this.clientSide ? 0 : 1));

            return new Promise<void>(async (resolve) => {
                this.qos1Buffer.set(dupID, data);
                this.qos1Wait.add(dupID);

                try {
                    for (let retry = false; ; retry = true) {
                        if (!this.connected) throw "no";

                        let packet = joinUint8Array([
                            0x01,
                            (dupID >> 24) & 0xFF,
                            (dupID >> 16) & 0xFF,
                            (dupID >> 8) & 0xFF,
                            dupID & 0xFF,
                            retry ? 0x01 : 0x00
                        ], data);

                        let pr: () => void, waitResolve = new Promise<void>((resolve) => pr = resolve);
                        this.qos1ACKCallback.set(dupID, resolve);

                        this.wc!.send(packet);

                        try {
                            await Promise.race([
                                waitResolve,
                                new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 10000))
                            ]);

                            break;
                        } catch { }
                    }

                    this.qos1Wait.delete(dupID);
                    this.qos1Buffer.set(dupID, true);
                    resolve();
                } catch {
                    this.qos1ACKCallback.set(dupID, resolve);
                }
            }) as ConditionalSend<T>;
        } else {
            if (!this.wc) throw new Error("No connection");

            this.wc.send(joinUint8Array([0x03], data));

            return void 0 as ConditionalSend<T>;
        }
    }
}