import pkg from "superdilithium";
const { superDilithium } = pkg;

function Uint8ToHex(u8a: Uint8Array) {
    return Array.from(u8a, x => ('00' + x.toString(16)).slice(-2)).join('');
}

export async function keyGeneration() {
    let keyPair = await superDilithium.keyPair();
    let pkh = new Uint8Array(await crypto.subtle.digest("SHA-256", keyPair.publicKey));
    return {
        privateKey: Uint8ToHex(keyPair.privateKey),
        publicKey: Uint8ToHex(keyPair.publicKey),
        publicKeyHash: Uint8ToHex(pkh)
    }
}
