/**
 * Generate a PKCE code_verifier string (43-128 chars) from unreserved characters
 */
export function getCodeVerifier(length = 64): string {
    const min = 43;
    const max = 128;
    if (length < min || length > max) throw new Error(`code_verifier length must be between ${min} and ${max}`);
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~';
    const random = new Uint8Array(length);
    crypto.getRandomValues(random);
    return Array.from(random).map(v => chars[v % chars.length]).join('');
}
