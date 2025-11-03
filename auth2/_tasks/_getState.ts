import { doEncode } from './_doEncode';

export function getState(byteLength = 16): string {
    const random = new Uint8Array(byteLength);
    crypto.getRandomValues(random);
    // return base64url string (not URI-encoded) to avoid double encoding later
    return doEncode({ str: random.buffer });
}
