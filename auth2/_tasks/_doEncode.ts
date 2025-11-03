/**
 * Encode a string or ArrayBuffer into a URL-safe Base64 (base64url) string without padding.
 */
export function doEncode({ str }: { str: string | ArrayBuffer }): string {
    let bytes: Uint8Array;
    if (typeof str === 'string') {
        bytes = new TextEncoder().encode(str);
    } else {
        bytes = new Uint8Array(str);
    }

    // convert to binary string in chunks to avoid argument length limits
    const chunkSize = 0x8000; // 32KB
    let binary = '';
    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + chunkSize)));
    }

    // standard base64
    const b64 = btoa(binary);
    // base64url: replace +/ with -_ and trim padding =
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
