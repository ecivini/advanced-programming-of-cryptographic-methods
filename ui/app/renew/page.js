'use client';

import React, { useState, useEffect } from 'react';

const CA_URL = process.env.NEXT_PUBLIC_CA_URL || 'http://localhost:5000';

// Import crypto functions from sign page
function detectKeyType(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const byteLen = (b64.length * 3) / 4;
  if (/-----BEGIN EC PRIVATE KEY-----/.test(pem)) return 'ECDSA';
  if (byteLen > 4000) return 'RSA_4096';
  if (byteLen > 300) return 'RSA_2048';
  return 'ECDSA';
}

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

async function signMessage(pem, message) {
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

export default function RenewPage() {
  const [serialNumber, setSerialNumber] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [isRenewing, setIsRenewing] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  // Check for serial number in URL on page load
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const urlParams = new URLSearchParams(window.location.search);
      const serial = urlParams.get('serial');
      if (serial) {
        setSerialNumber(serial);
      }
    }
  }, []);

  // Handle private key file upload
  const handlePrivateKeyUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setPrivateKey(e.target.result);
      };
      reader.readAsText(file);
    }
  };

  // Renew certificate
  const renewCertificate = async () => {
    if (!serialNumber.trim() || !privateKey.trim()) {
      setError('Please provide a serial number and your private key');
      return;
    }

    setIsRenewing(true);
    setError(null);
    setSuccess(false);

    try {
      // Auto-generate renewal message
      const renewalMessage = `Renew: ${serialNumber}`;
      
      // Sign the renewal message
      const signature = await signMessage(privateKey, renewalMessage);

      // Send renewal request to CA
      const response = await fetch(`${CA_URL}/v1/certificate/renew`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          serial_number: serialNumber,
          signature: signature
        }),
      });

      if (!response.ok) {
        let errorMessage;
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          const errorData = await response.json();
          errorMessage = errorData.error || JSON.stringify(errorData);
        } else {
          errorMessage = await response.text();
        }
        throw new Error(errorMessage || `Renewal failed: HTTP ${response.status}`);
      }

      setSuccess(true);
      setError('✅ Certificate renewed successfully!');
    } catch (error) {
      console.error('Certificate renewal error:', error);
      setError(`❌ Renewal failed: ${error.message}`);
    } finally {
      setIsRenewing(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-12 h-12 bg-gradient-to-r from-green-500 to-green-600 rounded-2xl mb-4">
          <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </div>
        <h1 className="text-3xl font-bold text-slate-800 mb-2">Renew Certificate</h1>
        <p className="text-slate-600">Sign a message to renew a certificate from the Certificate Authority</p>
      </div>

      {/* Navigation Back */}
      <div className="mb-6">
        <button
          onClick={() => window.history.back()}
          className="btn btn-secondary"
        >
          <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
          Back to Certificates
        </button>
      </div>

      {success ? (
        // Success message
        <div className="card p-6">
          <div className="text-center">
            <div className="inline-flex items-center justify-center w-12 h-12 bg-gradient-to-r from-green-500 to-green-600 rounded-2xl mb-4">
              <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h2 className="text-2xl font-bold text-slate-800 mb-2">Certificate Renewed Successfully</h2>
            <p className="text-slate-600 mb-6">The certificate has been renewed and a new certificate has been issued</p>
            <div className="flex gap-4 justify-center">
              <button
                onClick={() => {
                  setSuccess(false);
                  setSerialNumber('');
                  setPrivateKey('');
                  setError(null);
                }}
                className="btn btn-primary"
              >
                Renew Another Certificate
              </button>
              <button
                onClick={() => window.location.href = '/certs'}
                className="btn btn-secondary"
              >
                View Certificates
              </button>
            </div>
          </div>
        </div>
      ) : (
        // Renewal form
        <div className="card p-6">
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-800 p-4 rounded-lg mb-6">
              <div className="flex items-center">
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {error}
              </div>
            </div>
          )}

          <div className="max-w-2xl mx-auto space-y-6">
            {/* Certificate Serial Number */}
            <div>
              <label className="label">Certificate Serial Number</label>
              <input
                type="text"
                className="input font-mono"
                placeholder="Enter certificate serial number..."
                value={serialNumber}
                onChange={(e) => setSerialNumber(e.target.value)}
                disabled={isRenewing}
              />
              <p className="text-sm text-slate-500 mt-2">
                Enter the full serial number of the certificate you want to renew.
              </p>
            </div>

            {/* Show auto-generated message info */}
            {serialNumber && (
              <div className="bg-green-50 border border-green-200 p-4 rounded-lg">
                <label className="text-sm font-medium text-green-800 block mb-2">Auto-generated Message to Sign</label>
                <p className="text-green-700 font-mono text-sm break-all bg-white p-2 rounded border">
                  Renew: {serialNumber}
                </p>
                <p className="text-xs text-green-600 mt-2">
                  This message will be automatically signed with your private key to authorize the renewal.
                </p>
              </div>
            )}

            {/* Private Key */}
            <div>
              <label className="label">Private Key (PEM format)</label>
              <div className="space-y-3">
                <div className="flex gap-2">
                  <input
                    type="file"
                    accept=".pem,.key,.txt"
                    onChange={handlePrivateKeyUpload}
                    className="hidden"
                    id="privateKeyFileInput"
                    disabled={isRenewing}
                  />
                  <label
                    htmlFor="privateKeyFileInput"
                    className={`btn btn-secondary cursor-pointer ${isRenewing ? 'opacity-50 cursor-not-allowed' : ''}`}
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                    </svg>
                    Upload Private Key
                  </label>
                  <span className="text-sm text-slate-500 self-center">or paste below</span>
                </div>
                <textarea
                  rows={6}
                  className="input font-mono resize-none"
                  placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                  value={privateKey}
                  onChange={(e) => setPrivateKey(e.target.value)}
                  disabled={isRenewing}
                />
              </div>
              <p className="text-sm text-slate-500 mt-2">
                Your private key (PKCS#8, PKCS#1, or SEC1 format). Supports RSA and ECDSA keys.
              </p>
            </div>
            
            {/* Submit Button */}
            <button
              onClick={renewCertificate}
              disabled={isRenewing || !privateKey.trim() || !serialNumber.trim()}
              className={`btn btn-primary w-full ${
                isRenewing || !privateKey.trim() || !serialNumber.trim() ? 'opacity-50 cursor-not-allowed' : ''
              }`}
            >
              {isRenewing ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                  Renewing Certificate...
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  Sign Message & Renew Certificate
                </>
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
