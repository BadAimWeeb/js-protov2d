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
