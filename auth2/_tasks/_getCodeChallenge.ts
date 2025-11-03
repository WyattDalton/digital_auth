import { doEncode } from './_doEncode';

export async function getCodeChallenge(verifier: string): Promise<string> {
    const data = new TextEncoder().encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return doEncode({ str: digest });
}
