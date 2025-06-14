'use client';

import React, { useState } from 'react';

const CA_URL = process.env.NEXT_PUBLIC_CA_URL || 'http://localhost:5000';

// Detect key type and size from PEM
function detectKeyType(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const byteLen = (b64.length * 3) / 4;
  if (/-----BEGIN EC PRIVATE KEY-----/.test(pem)) return 'ECDSA';
  if (byteLen > 4000) return 'RSA_4096';
  if (byteLen > 300) return 'RSA_2048';
  return 'ECDSA';
}

// Convert PKCS#1 (traditional RSA) to PKCS#8
function convertPKCS1toPKCS8(pkcs1) {
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
function convertSEC1toPKCS8(sec1) {
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
function encodeECDSASignatureToDER(r, s) {
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
async function importPrivateKey(pem) {
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
  if (/-----BEGIN RSA PRIVATE KEY-----/.test(pem)) {
    const pkcs8 = convertPKCS1toPKCS8(bin);
    return crypto.subtle.importKey(
      'pkcs8', pkcs8.buffer,
      { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
      false, ['sign']
    );
  }
  const alg = detectKeyType(pem).startsWith('ECDSA')
    ? { name: 'ECDSA', namedCurve: 'P-256' }
    : { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };
  return crypto.subtle.importKey(
    'pkcs8', bin.buffer,
    alg, false, ['sign']
  );
}

// Sign the base64 challenge and return properly encoded signature
async function signChallenge(pem, challengeB64) {
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

export default function SignPage() {
  const [challenge, setChallenge] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [status, setStatus] = useState(null);
  const [certificate, setCertificate] = useState('');

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setPrivateKey(reader.result);
    reader.readAsText(file);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setStatus('Signing challenge...');
    setIsLoading(true);
    
    try {
      const challengeTrimmed = challenge.trim();
      
      // Validate base64 challenge
      try {
        atob(challengeTrimmed);
      } catch {
        throw new Error('Invalid base64 challenge format');
      }

      // Sign the challenge
      const signature = await signChallenge(privateKey, challengeTrimmed);
      setStatus('Requesting certificate...');

      // Request certificate from CA
      const response = await fetch(`${CA_URL}/v1/certificate`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          signature: signature, 
          challenge: challengeTrimmed 
        }),
      });

      const contentType = response.headers.get('content-type') || '';
      
      if (!response.ok) {
        let errorMessage;
        if (contentType.includes('application/json')) {
          const errorData = await response.json();
          errorMessage = errorData.error || JSON.stringify(errorData);
        } else {
          errorMessage = await response.text();
        }
        throw new Error(errorMessage || `Certificate request failed: HTTP ${response.status}`);
      }

      // Parse response
      const data = contentType.includes('application/json')
        ? await response.json()
        : { certificate: await response.text() };

      setCertificate(data.certificate);
      setStatus('✅ Certificate generated successfully!');
    } catch (error) {
      console.error('Certificate signing error:', error);
      setStatus(`❌ Error: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const downloadCertificate = () => {
    const blob = new Blob([certificate], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'certificate.pem';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
      .then(() => setStatus('✅ Copied to clipboard'))
      .catch(() => setStatus('❌ Copy failed'));
  };

  return (
    <div className="max-w-2xl mx-auto">
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-12 h-12 bg-gradient-to-r from-blue-500 to-blue-600 rounded-2xl mb-4">
          <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m0 0l0 0m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
        <h1 className="text-3xl font-bold text-slate-800 mb-2">Sign Certificate</h1>
        <p className="text-slate-600">Use your private key to sign the challenge and obtain your certificate</p>
      </div>

      <div className="card p-8">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="label">Challenge (Base64)</label>
            <textarea
              required
              rows={3}
              className="input font-mono resize-none"
              placeholder="Base64-encoded challenge from your email..."
              value={challenge}
              onChange={(e) => setChallenge(e.target.value)}
              disabled={isLoading}
            />
            <p className="text-sm text-slate-500 mt-2">Paste the base64-encoded challenge you received via email</p>
          </div>

          <div>
            <label className="label">Private Key (PEM format)</label>
            <div className="space-y-3">
              <div className="flex gap-2">
                <input
                  type="file"
                  accept=".pem,.key,.txt"
                  onChange={handleFileUpload}
                  className="hidden"
                  id="privateKeyFileInput"
                  disabled={isLoading}
                />
                <label
                  htmlFor="privateKeyFileInput"
                  className={`btn btn-secondary cursor-pointer ${isLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                  </svg>
                  Upload Private Key
                </label>
                <span className="text-sm text-slate-500 self-center">or paste below</span>
              </div>
              <textarea
                required
                rows={8}
                className="input font-mono resize-none"
                placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                value={privateKey}
                onChange={(e) => setPrivateKey(e.target.value)}
                disabled={isLoading}
              />
            </div>
            <p className="text-sm text-slate-500 mt-2">
              Your private key (PKCS#8, PKCS#1, or SEC1 format). Supports RSA and ECDSA keys.
            </p>
          </div>

          <button
            type="submit"
            disabled={isLoading || !challenge.trim() || !privateKey.trim()}
            className={`btn btn-primary w-full ${isLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {isLoading ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                Processing...
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                </svg>
                Sign & Request Certificate
              </>
            )}
          </button>
        </form>

        {status && (
          <div className={`mt-6 p-4 rounded-lg ${
            status.includes('✅') 
              ? 'bg-green-50 border border-green-200 text-green-800' 
              : status.includes('❌')
              ? 'bg-red-50 border border-red-200 text-red-800'
              : 'bg-blue-50 border border-blue-200 text-blue-800'
          }`}>
            <div className="flex items-center">
              {status.includes('✅') && (
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              )}
              {status.includes('❌') && (
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              )}
              {!status.includes('✅') && !status.includes('❌') && (
                <svg className="w-5 h-5 mr-2 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              )}
              {status}
            </div>
          </div>
        )}

        {certificate && (
          <div className="mt-6 p-6 bg-slate-50 border border-slate-200 rounded-lg">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-slate-800">Your Certificate</h2>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => copyToClipboard(certificate)}
                  className="btn btn-secondary text-sm"
                  title="Copy to clipboard"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                  Copy
                </button>
                <button
                  onClick={downloadCertificate}
                  className="btn btn-primary text-sm"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  Download
                </button>
              </div>
            </div>
            <pre className="bg-white p-4 rounded border text-sm font-mono overflow-auto max-h-96 text-slate-700">
              {certificate}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
