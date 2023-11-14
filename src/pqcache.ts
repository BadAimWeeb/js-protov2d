import Kyber, { type KEM as KyberKEM } from "@dashlane/pqc-kem-kyber1024-browser";
import Dilithium5, { type SIGN as Dilithium5SIGN } from "@dashlane/pqc-sign-dilithium5-browser";

let kyberCacheNonWASM: KyberKEM;
let kyberCacheWASM: KyberKEM;
let dilithium5CacheNonWASM: Dilithium5SIGN;
let dilithium5CacheWASM: Dilithium5SIGN;

export async function getKyber(disableWASM: boolean) {
    if (disableWASM) {
        if (!kyberCacheNonWASM) {
            kyberCacheNonWASM = await Kyber(true);
        }
        return kyberCacheNonWASM;
    } else {
        if (!kyberCacheWASM) {
            kyberCacheWASM = await Kyber(false);
        }
        return kyberCacheWASM;
    }
}

export async function getDilithium5(disableWASM: boolean) {
    if (disableWASM) {
        if (!dilithium5CacheNonWASM) {
            dilithium5CacheNonWASM = await Dilithium5(true);
        }
        return dilithium5CacheNonWASM;
    } else {
        if (!dilithium5CacheWASM) {
            dilithium5CacheWASM = await Dilithium5(false);
        }
        return dilithium5CacheWASM;
    }
}
