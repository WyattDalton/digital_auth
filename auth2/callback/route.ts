import { NextRequest } from 'next/server';
import { setKvToken } from '../_tasks/_doSetKv-token';

function parseCookies(cookieHeader?: string | null) {
    const cookies: Record<string, string> = {};
    if (!cookieHeader) return cookies;
    for (const part of cookieHeader.split(',')) {
        for (const kv of part.split(';')) {
            const [k, ...v] = kv.trim().split('=');
            if (!k) continue;
            cookies[k] = decodeURIComponent(v.join('='));
        }
    }
    return cookies;
}

export async function GET(req: Request) {
    const url = new URL(req.url);
    const code = url.searchParams.get('code');
    const returnedState = url.searchParams.get('state');

    const cookies = parseCookies(req.headers.get('cookie'));
    const storedState = cookies['oauth_state'];
    const code_verifier = cookies['pkce_code_verifier'];

    if (!code || !returnedState) {
        return new Response(JSON.stringify({ error: 'Missing code or state in callback' }), { status: 400 });
    }
    if (!storedState || returnedState !== storedState) {
        return new Response(JSON.stringify({ error: 'Invalid state' }), { status: 400 });
    }
    if (!code_verifier) {
        return new Response(JSON.stringify({ error: 'Missing code_verifier cookie' }), { status: 400 });
    }

    const clientId = process.env.DIGITAIL_CLIENT_ID;
    const clientSecret = process.env.DIGITAIL_CLIENT_SECRET;
    const redirectUri = process.env.DIGITAIL_REDIRECT_URI;
    if (!clientId || !clientSecret || !redirectUri) {
        return new Response(JSON.stringify({ error: 'Missing DIGITAIL env vars' }), { status: 500 });
    }

    const body = new URLSearchParams();
    body.append('grant_type', 'authorization_code');
    body.append('client_id', clientId);
    body.append('client_secret', clientSecret);
    body.append('redirect_uri', redirectUri);
    body.append('code_verifier', code_verifier);
    body.append('code', code);

    const tokenRes = await fetch('https://vet.digitail.io/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString()
    });

    const tokenJson = await tokenRes.json();

    // Clear the PKCE cookies (set expired)
    const clearVerifier = 'pkce_code_verifier=; Path=/api/vet_records/auth2; Max-Age=0; HttpOnly; Secure; SameSite=Lax';
    const clearState = 'oauth_state=; Path=/api/vet_records/auth2; Max-Age=0; HttpOnly; Secure; SameSite=Lax';

    // If token fetch was successful, store tokens in KV
    if (tokenRes.ok) {
        const storeResult = await setKvToken(tokenJson);
        if (!storeResult) {
            return new Response(JSON.stringify({ error: 'Failed to store tokens in KV' }), {
                status: 500,
                headers: { 'Set-Cookie': `${clearVerifier}, ${clearState}` }
            });
        }
    }

    // Return tokens (or error payload) and clear cookies
    return new Response(JSON.stringify(tokenJson), {
        status: tokenRes.ok ? 200 : 400,
        headers: { 'Content-Type': 'application/json', 'Set-Cookie': `${clearVerifier}, ${clearState}` }
    });
}
