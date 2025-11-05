import { getCodeVerifier } from '../_tasks/_getCodeVerifier';
import { getCodeChallenge } from '../_tasks/_getCodeChallenge';
import { getState } from '../_tasks/_getState';

function makeCookie(name: string, value: string, options: { path?: string; maxAge?: number } = {}) {
    const parts = [`${name}=${encodeURIComponent(value)}`];
    parts.push(`Path=${options.path ?? '/api/vet_records/auth2'}`);
    if (options.maxAge) parts.push(`Max-Age=${options.maxAge}`);
    parts.push('HttpOnly');
    parts.push('SameSite=Lax');
    parts.push('Secure');
    return parts.join('; ');
}

export async function GET(req: Request) {
    const clientId = process.env.DIGITAIL_CLIENT_ID;
    const clientSecret = process.env.DIGITAIL_CLIENT_SECRET;
    const redirectUri = process.env.DIGITAIL_REDIRECT_URI; // must match registered
    if (!clientId || !redirectUri) {
        return new Response(JSON.stringify({ error: 'Missing DIGITAIL_CLIENT_ID or DIGITAIL_REDIRECT_URI' }), { status: 500 });
    }

    const code_verifier = getCodeVerifier(64);
    const state = getState(16);
    const code_challenge = await getCodeChallenge(code_verifier);

    // store code_verifier and state in httpOnly cookies so callback can read them
    const cookieVerifier = makeCookie('pkce_code_verifier', code_verifier, { maxAge: 600 });
    const cookieState = makeCookie('oauth_state', state, { maxAge: 600 });

    const params = new URLSearchParams();
    params.set('response_type', 'code');
    params.set('client_id', clientId);
    if (clientSecret) params.set('client_secret', clientSecret);
    params.set('redirect_uri', redirectUri);
    params.set('state', state);
    params.set('code_challenge', code_challenge);
    params.set('code_challenge_method', 'S256');

    const authUrl = `https://developer.digitail.io/oauth/authorize?${params.toString()}`;

    return new Response(null, {
        status: 307,
        headers: {
            Location: authUrl,
            'Set-Cookie': `${cookieVerifier}, ${cookieState}`
        }
    });
}
