export function stringToArrayBuffer(str) {
  return new TextEncoder().encode(str);
}

export async function importPrivateKey(pem) {
  // strip headers
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s+/g, '');
  const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'pkcs8',
    der.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

export function signData(key, data) {
  return crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    data
  );
}
