import Dilithium5, { type SIGN as Dilithium5SIGN } from "@dashlane/pqc-sign-dilithium5-browser";
import { ed25519 } from "@noble/curves/ed25519";
import { joinUint8Array, Uint8ArrayToHex } from "./utils.js";

export async function keyGeneration() {
    let D5 = await Dilithium5(true); // use JS only, this is more like one time thing so we don't care about performance

    let pqKeyPair = await D5.keypair();
    let classicPrivateKey = crypto.getRandomValues(new Uint8Array(32));
    let classicPublicKey = ed25519.getPublicKey(classicPrivateKey);

    let keyPair = {
        privateKey: joinUint8Array(classicPrivateKey, pqKeyPair.privateKey),
        publicKey: joinUint8Array(classicPublicKey, pqKeyPair.publicKey)
    };

    let pkh = new Uint8Array(await crypto.subtle.digest("SHA-256", keyPair.publicKey));
    return {
        privateKey: Uint8ArrayToHex(keyPair.privateKey),
        publicKey: Uint8ArrayToHex(keyPair.publicKey),
        publicKeyHash: Uint8ArrayToHex(pkh)
    }
}
