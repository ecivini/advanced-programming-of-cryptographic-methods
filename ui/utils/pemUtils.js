export async function fromPEMToPrivateKey(pem) {
    try {
        const b64 = pem
        .replace('-----BEGIN PRIVATE KEY-----', '')
        .replace('-----END PRIVATE KEY-----', '')
        .replace(/\s+/g, '');
        const binary = Uint8Array.from(atob(b64), c => c.charCodeAt(0));

        return await crypto.subtle.importKey(
        'pkcs8',
        binary.buffer,
        {
            name: 'ECDSA',
            namedCurve: 'P-256',
        },
        false,
        ['sign']
        );
    } catch (err) {
        console.error('[PEM import error]', err);
        return null;
    }
}
