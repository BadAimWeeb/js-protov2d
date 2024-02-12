import { TypedEmitter } from "tiny-typed-emitter";
import { WrappedConnection } from "./connection";
import { aesDecrypt, aesEncrypt, joinUint8Array } from "./utils.js";
import debug from "debug";

const log = debug("protov2d:session");
const logDisconnect = debug("protov2d:session:disconnect");

interface ProtoV2dSessionEvent {
    /** Use this to receive data */
    'data': (QoS: 0 | 1, data: Uint8Array) => void;

    /** For internal purposes only: Also captures raw packet that will send to other side */
    'data_ret': (data: Uint8Array) => void;

    /** Close */
    'closed': () => void;

    /* Signal */
    'disconnected': () => void;
    'connected': () => void;
    'resumeFailed': (newStream: ProtoV2dSession) => void;
    'wcChanged': (oldWC: WrappedConnection | null, newWC: WrappedConnection | null) => void;

    /** Ping */
    'ping': (ping: number) => void;

    /** Final close. This will be emitted by client reconnection handler. No reconnection will be made. */
    'finalClose': () => void;

    //[k: string]: (...args: any[]) => any;
}

/**
 * The session object represents a ProtoV2d connection between client and server. It is the main way to receive and send data.
 * 
 * Contains logic used after handshake.
 */
export default class ProtoV2dSession<BackendData = any> extends TypedEmitter<ProtoV2dSessionEvent> {
    closed = false;

    get connected() {
        return !(this.wc || { closed: true }).closed;
    }

    //qos1Buffer: [dupID: number, data: Uint8Array][] = [];
    private _qos1Buffer = new Map<number, Uint8Array | true>();
    private _qos1Wait = new Set<number>();
    private _qos1ACKCallback = new Map<number, () => void>();
    private _qos1Counter: number = 0;
    private _pingClock: ReturnType<typeof setInterval> | null = null;

    private _wc: WrappedConnection<BackendData> | null;
    get wc() {
        return this._wc;
    }

    set wc(wc: WrappedConnection<BackendData> | null) {
        let oldWC = this._wc;
        if (oldWC) this._handleOldWC(oldWC);

        this.emit("wcChanged", this._wc, wc);
        this.emit("connected");
        this._wc = wc;
        if (wc) this._handleWC(wc);
        if (oldWC) this._handleOldWC2(oldWC);
    }

    private _ping = Infinity;
    private _pings: number[] = [];
    get ping() {
        return this._ping;
    }

    get avgPing() {
        return this._pings.reduce((a, b) => a + b, 0) / this._pings.length;
    }

    private _encryption: CryptoKey[];
    set encryption(key: CryptoKey[]) {
        this._encryption = key;
    }

    constructor(public connectionPK: string, public protocolVersion: number, public clientSide: boolean, wc: WrappedConnection<BackendData>, encryption: CryptoKey[], public timeout = 10000, public pingInterval = 15000, public avgPingCount = 10) {
        super();
        this._wc = wc;
        this._encryption = encryption;
        this._handleWC(wc);
    }

    private async _decrypt(data: Uint8Array) {
        let dKey: CryptoKey;
        let dKeysCopy = this._encryption.slice();
        while (dKey = dKeysCopy.pop()!) {
            data = await aesDecrypt(data, dKey, this.protocolVersion !== 1);
        }
        return data;
    }

    private async _encrypt(data: Uint8Array) {
        let eKey: CryptoKey;
        let eKeysCopy = this._encryption.slice();
        while (eKey = eKeysCopy.shift()!) {
            data = await aesEncrypt(data, eKey, this.protocolVersion !== 1);
        }
        return data;
    }

    private async _generatePing() {
        if (!this.connected || !this._wc) return;
        let wc = this._wc;

        let startPing = Date.now();
        let randomBytes = crypto.getRandomValues(new Uint8Array(16));
        let resolvePromise: () => void, promise = new Promise<void>((resolve) => resolvePromise = resolve);
        let handlePingPacket = (data: Uint8Array) => {
            if (data[0] !== 0x04) return;
            if (data[1] !== 0x01) return;
            if (data.length !== 18) return;
            // Compare random bytes
            for (let i = 0; i < 16; i++) {
                if (data[i + 2] !== randomBytes[i]) return;
            }
            wc.removeListener("rx", handlePingPacket);
            resolvePromise();
        }
        wc.on("rx", handlePingPacket);

        // Ping packet
        wc.send(joinUint8Array([0x04, 0x00], randomBytes));

        // Wait for pong packet, if timed out in 10 seconds, then close connection
        try {
            await Promise.race([
                promise,
                new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), this.timeout))
            ]);

            this._ping = Date.now() - startPing;
            this._pings.push(this._ping);
            if (this._pings.length > this.avgPingCount) this._pings.shift();
            this.emit("ping", this._ping);
        } catch {
            wc.emit("close", false, "Ping ACK timeout");
        }
    }

    // maybe be a little bit slower.
    private _waitPromise: Promise<void> | null = null;
    private _handleWC(wc: WrappedConnection) {
        wc.on("rx", this._bindHandleIncomingWCMessage);
        wc.on("close", this._bindHandleWCCloseEvent);

        this._pingClock = setInterval(() => this._generatePing(), this.pingInterval);
        if (this.clientSide) {
            this._generatePing(); // Generate ping immediately

            // Retry unsuccessful QoS1
            for (let dupID of this._qos1Wait) {
                (async () => {
                    if (!this._qos1Buffer.has(dupID)) return;

                    let originalResolve = this._qos1ACKCallback.get(dupID);
                    let data = this._qos1Buffer.get(dupID)! as Uint8Array;

                    try {
                        await this.send(1, data, dupID);
                        originalResolve?.();
                    } catch { }
                })();
            }
        } else {
            // If we're in server side, we don't want to send the ping packet too fast,
            // otherwise client (which still haven't done resolving handshake yet) will be confused
            // and close the connection.
            // Wait for first ping packet from client before sending our own ping packet (and unsuccessful data).
            let resolvePromise: () => void;
            this._waitPromise = new Promise<void>((resolve) => resolvePromise = resolve);

            function handlePingPacket(data: Uint8Array) {
                if (data[0] !== 0x04) return;
                if (data[1] !== 0x00) return;

                wc.removeListener("rx", handlePingPacket);
                resolvePromise();
            }
            wc.on("rx", handlePingPacket);

            this._waitPromise.then(() => this._generatePing());
            this._waitPromise.then(() => {
                // Retry unsuccessful QoS1
                for (let dupID of this._qos1Wait) {
                    (async () => {
                        if (!this._qos1Buffer.has(dupID)) return;

                        let originalResolve = this._qos1ACKCallback.get(dupID);
                        let data = this._qos1Buffer.get(dupID)! as Uint8Array;

                        try {
                            await this.send(1, data, dupID);
                            originalResolve?.();
                        } catch { }
                    })();
                }
            });
        }
    }

    private _handleOldWC(wc: WrappedConnection) {
        wc.removeListener("rx", this._bindHandleIncomingWCMessage);
        wc.removeListener("close", this._bindHandleWCCloseEvent);
        if (this._pingClock) {
            clearInterval(this._pingClock);
            this._pingClock = null;
        }
        this._waitPromise = null;
    }

    private _handleOldWC2(wc: WrappedConnection) {
        // Disconnect old WC after swapped with new WC
        wc.emit("close", true, "Replaced by new WC");
    }

    //#region Event stuff
    private async _handleIncomingWCMessage(data: Uint8Array) {
        switch (data[0]) {
            // Data 
            case 0x03: {
                let packet = await this._decrypt(data.slice(1));

                let qos = packet[0];
                switch (qos) {
                    case 0x00: {
                        log(`incoming qos0 data`);

                        this.emit("data", 0, packet.slice(1));
                        break;
                    }

                    case 0x01: {
                        let dupID = (packet[1] << 24) | (packet[2] << 16) | (packet[3] << 8) | packet[4];
                        let control = packet[5];

                        if (control === 0xFF) {
                            log(`incoming qos1 ack ${dupID}`);

                            if (!this._qos1Wait.has(dupID)) return;
                            this._qos1ACKCallback.get(dupID)?.();
                            this._qos1ACKCallback.delete(dupID);
                        } else {
                            log(`incoming qos1 data ${dupID}`);

                            let data = packet.slice(6);

                            if (!this._qos1Buffer.has(dupID)) {
                                this._qos1Buffer.set(dupID, true);
                                this.emit("data", 1, data);
                            }

                            this._wc?.send(joinUint8Array([0x03], await this._encrypt(joinUint8Array([
                                0x01,
                                (dupID >> 24) & 0xFF,
                                (dupID >> 16) & 0xFF,
                                (dupID >> 8) & 0xFF,
                                dupID & 0xFF,
                                0xFF
                            ]))));
                        }
                        break;
                    }
                }
                return;
            }

            case 0x04: {
                if (data[1] === 0x00) {
                    this._wc?.send(joinUint8Array([0x04, 0x01], data.slice(2)));
                }
                return;
            }

            // Graceful close
            case 0x05: {
                this.close();
                return;
            }
        }
    }
    private _bindHandleIncomingWCMessage = this._handleIncomingWCMessage.bind(this);

    private _handleWCCloseEvent(explict: boolean, reason?: string) {
        logDisconnect(`wc close event: explict %s, reason %s`, explict, reason);
        this.emit("disconnected");
        this.wc!.removeListener("close", this._bindHandleWCCloseEvent);
    }
    private _bindHandleWCCloseEvent = this._handleWCCloseEvent.bind(this);
    //#endregion

    /** Destroy object without destroying WC. All listener will be removed to make this object GC-able. WC pointer will also be null. */
    public destroy() {
        if (this._wc) this.emit("wcChanged", this._wc, null);
        this._wc = null;
        if (!this.closed) this.emit("closed");
        this.closed = true;
        this._qos1Buffer.clear();
        this._qos1Wait.clear();
        this._qos1ACKCallback.clear();
        this.removeAllListeners();
    }

    /** Close connection and destory object. All listener will be removed to make this object GC-able. WC pointer will also be null. */
    public close(reason?: string) {
        if (!this.closed) this.emit("closed");
        this.closed = true;
        if (this._wc) {
            this._wc.emit("close", true, reason);
            this.emit("wcChanged", this._wc, null);
        }
        this._wc = null;
        this._qos1Buffer.clear();
        this._qos1Wait.clear();
        this._qos1ACKCallback.clear();
        this.removeAllListeners();
    }

    /** Send data to other side */
    public async send(QoS: 0 | 1, data: Uint8Array, overrideDupID?: number): Promise<void> {
        // maybe we should wait for the handshake and ping to be done first
        await this._waitPromise;

        if (QoS === 1) {
            let dupID = overrideDupID ?? ((this._qos1Counter++ << 1) | (this.clientSide ? 0 : 1));

            return new Promise<void>(async (resolve) => {
                this._qos1Buffer.set(dupID, data);
                this._qos1Wait.add(dupID);

                try {
                    for (let retry = false; ; retry = true) {
                        if (!this.connected) throw "no";

                        let packet = await this._encrypt(joinUint8Array([
                            0x01,
                            (dupID >> 24) & 0xFF,
                            (dupID >> 16) & 0xFF,
                            (dupID >> 8) & 0xFF,
                            dupID & 0xFF,
                            retry ? 0x01 : 0x00
                        ], data));

                        let pr = () => { }, waitResolve = new Promise<void>((resolve) => pr = resolve);
                        this._qos1ACKCallback.set(dupID, pr);

                        this.wc?.send(joinUint8Array([0x03], packet));

                        try {
                            await Promise.race([
                                waitResolve,
                                new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 10000))
                            ]);

                            break;
                        } catch { }
                    }

                    this._qos1Wait.delete(dupID);
                    this._qos1Buffer.set(dupID, true);
                    resolve();
                } catch {
                    this._qos1ACKCallback.set(dupID, resolve);
                }
            });
        } else {
            this.wc?.send(await this._encrypt(joinUint8Array([0x00], data)));
        }
    }
}