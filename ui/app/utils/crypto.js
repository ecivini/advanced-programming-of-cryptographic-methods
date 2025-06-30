// Shared cryptographic utilities for certificate operations

// Convert PKCS#1 (traditional RSA) to PKCS#8
export function convertPKCS1toPKCS8(pkcs1) {
  const version = Uint8Array.from([0x02, 0x01, 0x00]);
  const rsaOID = Uint8Array.from([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
  const pkcs1Len = pkcs1.length;
  let wrapper;
  if (pkcs1Len < 0x80) {
    wrapper = Uint8Array.from([0x04, pkcs1Len]);
  } else if (pkcs1Len < 0x100) {
    wrapper = Uint8Array.from([0x04, 0x81, pkcs1Len]);
  } else {
    wrapper = Uint8Array.from([0x04, 0x82, (pkcs1Len >> 8), (pkcs1Len & 0xff)]);
  }
  const content = new Uint8Array([...version, ...rsaOID, ...wrapper, ...pkcs1]);
  const totalLen = content.length;
  let seq;
  if (totalLen < 0x80) {
    seq = Uint8Array.from([0x30, totalLen]);
  } else if (totalLen < 0x100) {
    seq = Uint8Array.from([0x30, 0x81, totalLen]);
  } else {
    seq = Uint8Array.from([0x30, 0x82, (totalLen >> 8), (totalLen & 0xff)]);
  }
  return new Uint8Array([...seq, ...content]);
}

// Convert SEC1 (traditional EC) to PKCS#8
export function convertSEC1toPKCS8(sec1) {
  const version = Uint8Array.from([0x02, 0x01, 0x00]);
  const ecOID = Uint8Array.from([0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07]);
  const privOctet = Uint8Array.from([0x04, sec1.length]);
  const content = new Uint8Array([...version, ...ecOID, ...privOctet, ...sec1]);
  const totalLen = content.length;
  let seq;
  if (totalLen < 0x80) {
    seq = Uint8Array.from([0x30, totalLen]);
  } else if (totalLen < 0x100) {
    seq = Uint8Array.from([0x30, 0x81, totalLen]);
  } else {
    seq = Uint8Array.from([0x30, 0x82, (totalLen >> 8), (totalLen & 0xff)]);
  }
  return new Uint8Array([...seq, ...content]);
}

// DER-encode raw ECDSA signature (r | s)
export function encodeECDSASignatureToDER(r, s) {
  const encodeInt = (i) => {
    let start = 0;
    while (start < i.length && i[start] === 0) start++;
    let trimmed = i.slice(start) || Uint8Array.from([0]);
    if (trimmed[0] & 0x80) {
      const prefixed = new Uint8Array(trimmed.length + 1);
      prefixed.set([0], 0);
      prefixed.set(trimmed, 1);
      trimmed = prefixed;
    }
    const len = trimmed.length;
    return Uint8Array.from([0x02, len, ...trimmed]);
  };
  const rDer = encodeInt(r);
  const sDer = encodeInt(s);
  const seqLen = rDer.length + sDer.length;
  const header = seqLen < 0x80
    ? Uint8Array.from([0x30, seqLen])
    : Uint8Array.from([0x30, 0x81, seqLen]);
  return new Uint8Array([...header, ...rDer, ...sDer]);
}

// Import PEM private key for signing
export async function importPrivateKey(pem) {
  const raw = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const bin = Uint8Array.from(atob(raw), c => c.charCodeAt(0));
  if (/-----BEGIN EC PRIVATE KEY-----/.test(pem)) {
    const pkcs8 = convertSEC1toPKCS8(bin);
    return crypto.subtle.importKey(
      'pkcs8', pkcs8.buffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false, ['sign']
    );
  }
  else if (/-----BEGIN RSA PRIVATE KEY-----/.test(pem)) {
    const pkcs8 = convertPKCS1toPKCS8(bin);
    return crypto.subtle.importKey(
      'pkcs8', pkcs8.buffer,
      { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
      false, ['sign']
    );
  } else if (/-----BEGIN PRIVATE KEY-----/.test(pem)) {
    return crypto.subtle.importKey(
      'pkcs8',  bin.buffer,
      { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
      false, ['sign']
    );
  }

  return null;
}

// Sign the base64 challenge and return properly encoded signature
export async function signChallenge(pem, challengeB64) {
  // import key and raw challenge bytes
  const key = await importPrivateKey(pem);
  const rawChallenge = Uint8Array.from(atob(challengeB64), c => c.charCodeAt(0));

  // choose algorithm based on key type
  const algParams = key.algorithm.name === 'ECDSA'
    ? { name: 'ECDSA', hash: { name: 'SHA-256' } }
    : { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };

  // generate signature ArrayBuffer
  const sigBuffer = await crypto.subtle.sign(algParams, key, rawChallenge);
  const sigBytes = new Uint8Array(sigBuffer);

  if (key.algorithm.name === 'ECDSA') {
    // Web Crypto ECDSA yields raw r|s concat; encode to DER
    const half = sigBytes.length / 2;
    const derSig = encodeECDSASignatureToDER(
      sigBytes.slice(0, half),
      sigBytes.slice(half)
    );
    return btoa(String.fromCharCode(...derSig));
  }

  // RSA: base64 of raw signature bytes
  return btoa(String.fromCharCode(...sigBytes));
}

// Sign a text message and return properly encoded signature (for revoke/renew operations)
export async function signMessage(pem, message) {
  const key = await importPrivateKey(pem);
  const messageBytes = new TextEncoder().encode(message);

  const algParams = key.algorithm.name === 'ECDSA'
    ? { name: 'ECDSA', hash: { name: 'SHA-256' } }
    : { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };

  const sigBuffer = await crypto.subtle.sign(algParams, key, messageBytes);
  const sigBytes = new Uint8Array(sigBuffer);

  if (key.algorithm.name === 'ECDSA') {
    const half = sigBytes.length / 2;
    const derSig = encodeECDSASignatureToDER(
      sigBytes.slice(0, half),
      sigBytes.slice(half)
    );
    return btoa(String.fromCharCode(...derSig));
  }

  return btoa(String.fromCharCode(...sigBytes));
}
