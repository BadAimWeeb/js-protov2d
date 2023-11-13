import { Address4, Address6 } from "ip-address";

export function randomString(length: number) {
    let result = "";
    let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

export function Uint8ArrayToHex(arr: Uint8Array) {
    return Array.from(arr).map((x) => x.toString(16).padStart(2, "0")).join("");
}

export function hexToUint8Array(hex: string) {
    return new Uint8Array(hex.match(/.{1,2}/g)!.map((x) => parseInt(x, 16)));
}

export function proxyTrustResolver(chainedIPs: string[], trustedIPs: (Address4 | Address6)[] | boolean) {
    let copiedChainedIPs = chainedIPs.slice();
    let realIP: Address4 | Address6 | null = null;

    if (trustedIPs) {
        if (Array.isArray(trustedIPs)) {
            let proxy: string;
            while (proxy = copiedChainedIPs.pop()!) {
                let proxyIPObject: Address4 | Address6;
                try {
                    proxyIPObject = new Address6(proxy);
                } catch {
                    try {
                        proxyIPObject = new Address4(proxy);
                    } catch {
                        break;
                    }
                }
                realIP = proxyIPObject; // Set current real IP

                for (let trustedProxy of trustedIPs) {
                    if (proxyIPObject.isInSubnet(trustedProxy)) {
                        // Trusted proxy
                        continue;
                    }
                }

                // Not trusted proxy
                break;
            }
        } else {
            try {
                realIP = new Address6(chainedIPs[0] ?? "");
            } catch {
                try {
                    realIP = new Address4(chainedIPs[0] ?? "");
                } catch { }
            }
        }
    } else {
        // Trust no proxies
        try {
            realIP = new Address6(chainedIPs.at(-1) ?? "");
        } catch {
            try {
                realIP = new Address4(chainedIPs.at(-1) ?? "");
            } catch { }
        }
    }

    return realIP;
}

export async function aesDecrypt(encryptedData: Uint8Array, key: CryptoKey, sha = false) {
    let decryptedData = await crypto.subtle.decrypt({
        name: "AES-GCM",
        iv: encryptedData.slice(0, 16),
        tagLength: 128,
    }, key, encryptedData.slice(sha ? 48 : 16));

    if (sha) {
        let sha256 = await crypto.subtle.digest("SHA-256", decryptedData);
        if (Uint8ArrayToHex(new Uint8Array(sha256)) !== Uint8ArrayToHex(encryptedData.slice(16, 48))) {
            throw new Error("SHA-256 mismatch");
        }
    }

    return new Uint8Array(decryptedData);
}

export async function aesEncrypt(data: Uint8Array, key: CryptoKey, sha = false) {
    let iv = crypto.getRandomValues(new Uint8Array(16));
    let encryptedData = await crypto.subtle.encrypt({
        name: "AES-GCM",
        iv,
        tagLength: 128,
    }, key, data);

    let shaData: Uint8Array;
    if (sha) {
        let sha256 = await crypto.subtle.digest("SHA-256", data);
        shaData = new Uint8Array(sha256);
    }

    let result = new Uint8Array((sha ? 48 : 16) + encryptedData.byteLength);
    result.set(iv);
    if (sha) {
        result.set(shaData!, 16);
    }
    result.set(new Uint8Array(encryptedData), sha ? 48 : 16);

    return result;
}

export function joinUint8Array(...rawArrays: (Uint8Array | number[])[]) {
    let arrays = rawArrays.map((x) => x instanceof Uint8Array ? x : Uint8Array.from(x));
    let length = arrays.reduce((a, b) => a + b.byteLength, 0);

    let result = new Uint8Array(length);
    let offset = 0;
    for (let array of arrays) {
        result.set(array, offset);
        offset += array.byteLength;
    }

    return result;
}

export function filterNull<T>(v: T | null | undefined): v is T {
    return v !== null && v !== undefined;
}
