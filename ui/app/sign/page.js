'use client';

import React, { useState } from 'react';

export default function SignPage() {
  const [challenge, setChallenge] = useState('');
  const [privateKeyPEM, setPrivateKeyPEM] = useState('');
  const [keyType, setKeyType] = useState('ECDSA');
  const [status, setStatus] = useState(null);
  const [certificate, setCertificate] = useState('');
  const [downloadUrl, setDownloadUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  // Handle file upload for private key
  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setPrivateKeyPEM(e.target.result);
      };
      reader.readAsText(file);
    }
  };

  // Handle copy to clipboard with modern API
  const copyToClipboard = async (text, successMessage) => {
    try {
      await navigator.clipboard.writeText(text);
      setStatus(`✅ ${successMessage}`);
      setTimeout(() => setStatus(null), 3000);
    } catch (err) {
      setStatus(`❌ Failed to copy: ${err.message}`);
    }
  };

  // Utility: parse a PEM-encoded block into an ArrayBuffer
  const pemToArrayBuffer = (pem) => {
    const b64 = pem
      .replace(/-----BEGIN [A-Z0-9 _]+-----/, '')
      .replace(/-----END [A-Z0-9 _]+-----/, '')
      .replace(/\s+/g, '');
    const binaryString = atob(b64);
    const byteArray = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      byteArray[i] = binaryString.charCodeAt(i);
    }
    return byteArray.buffer;
  };

  // Utility: convert ArrayBuffer → Base64
  const arrayBufferToBase64 = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setStatus('Generating signature...');
    setCertificate('');
    setDownloadUrl('');

    try {
      if (!challenge.trim()) {
        setStatus('Error: Challenge cannot be empty.');
        setIsLoading(false);
        return;
      }
      if (!privateKeyPEM.trim()) {
        setStatus('Error: Private key cannot be empty.');
        setIsLoading(false);
        return;
      }

      // Parse PEM → ArrayBuffer
      let keyBuffer;
      try {
        keyBuffer = pemToArrayBuffer(privateKeyPEM);
      } catch (parseErr) {
        setStatus('Error: Failed to decode PEM. Ensure it is correctly formatted.');
        setIsLoading(false);
        return;
      }

      // Import the private key via Web Crypto
      let cryptoKey;
      if (keyType === 'ECDSA') {
        // ECDSA expects a PKCS#8 encoded EC private key
        try {
          cryptoKey = await window.crypto.subtle.importKey(
            'pkcs8',
            keyBuffer,
            {
              name: 'ECDSA',
              namedCurve: 'P-256',
            },
            false,
            ['sign']
          );
        } catch (impErr) {
          console.error(impErr);
          setStatus('Error: Could not import ECDSA key. Ensure it is a P-256 PKCS#8 PEM.');
          setIsLoading(false);
          return;
        }
      } else {
        // RSA: only PKCS#8 is supported for private keys
        try {
          cryptoKey = await window.crypto.subtle.importKey(
            'pkcs8',
            keyBuffer,
            {
              name: 'RSASSA-PKCS1-v1_5',
              hash: 'SHA-256',
            },
            false,
            ['sign']
          );
        } catch (impErr) {
          console.error(impErr);
          setStatus('Error: Could not import RSA key. Ensure it is a valid PKCS#8 RSA PEM.');
          setIsLoading(false);
          return;
        }
      }

      // Encode the challenge as UTF-8
      const encoder = new TextEncoder();
      const challengeBuffer = encoder.encode(challenge);

      // Sign the challenge
      let signatureBuffer;
      if (keyType === 'ECDSA') {
        signatureBuffer = await window.crypto.subtle.sign(
          {
            name: 'ECDSA',
            hash: { name: 'SHA-256' },
          },
          cryptoKey,
          challengeBuffer
        );
      } else {
        signatureBuffer = await window.crypto.subtle.sign(
          {
            name: 'RSASSA-PKCS1-v1_5',
          },
          cryptoKey,
          challengeBuffer
        );
      }

      const signatureB64 = arrayBufferToBase64(signatureBuffer);
      setStatus('Submitting signature to CA for verification...');

      // Send to backend for verification & certificate generation
      const IdUrl = process.env.NEXT_PUBLIC_CA_URL + '/v1/identity/certificate';
      const res = await fetch(IdUrl, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          signature: signatureB64,
          challenge: challenge,
          key_type: keyType,
        }),
      });

      const json = await res.json();
      if (!res.ok) {
        throw new Error(json.error || 'Unknown error from CA');
      }

      const certPem = json.certificate;
      setCertificate(certPem);
      setStatus('✅ Certificate generated successfully.');

      const blob = new Blob([certPem], {
        type: 'application/x-pem-file',
      });
      const url = URL.createObjectURL(blob);
      setDownloadUrl(url);
    } catch (err) {
      console.error(err);
      setStatus(`❌ Error: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto">
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-12 h-12 bg-gradient-to-r from-blue-500 to-blue-600 rounded-2xl mb-4">
          <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
        </div>
        <h1 className="text-3xl font-bold text-slate-800 mb-2">Get Certificate</h1>
        <p className="text-slate-600">Sign your challenge to receive your digital certificate</p>
      </div>

      <div className="card p-8">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="label">Challenge Code</label>
            <textarea
              required
              rows={4}
              className="input font-mono resize-none"
              placeholder="Paste the challenge code from your email"
              value={challenge}
              onChange={e => setChallenge(e.target.value)}
            />
            <p className="text-sm text-slate-500 mt-2">Enter the challenge exactly as received in your email</p>
          </div>

          <div>
            <label className="label">Private Key (PKCS#8 format)</label>
            <div className="space-y-3">
              <div className="flex gap-2">
                <input
                  type="file"
                  accept=".pem,.key,.txt"
                  onChange={handleFileUpload}
                  className="hidden"
                  id="keyFileInput"
                />
                <label
                  htmlFor="keyFileInput"
                  className="btn btn-secondary cursor-pointer"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  Upload Key File
                </label>
                <span className="text-sm text-slate-500 self-center">or paste below</span>
              </div>
              <textarea
                required
                rows={8}
                className="input font-mono resize-none"
                placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                value={privateKeyPEM}
                onChange={e => setPrivateKeyPEM(e.target.value)}
              />
            </div>
            <p className="text-sm text-slate-500 mt-2">Your private key must be in PKCS#8 format. For ECDSA, use P-256 curve.</p>
          </div>

          <div>
            <label className="label">Key Type</label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <label className="flex items-center p-3 border rounded-lg cursor-pointer hover:bg-slate-50 transition-colors">
                <input
                  type="radio"
                  className="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 focus:ring-blue-500"
                  name="keyType"
                  value="ECDSA"
                  checked={keyType === 'ECDSA'}
                  onChange={() => setKeyType('ECDSA')}
                />
                <span className="ml-2 text-sm font-medium">ECDSA (P-256)</span>
              </label>
              <label className="flex items-center p-3 border rounded-lg cursor-pointer hover:bg-slate-50 transition-colors">
                <input
                  type="radio"
                  className="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 focus:ring-blue-500"
                  name="keyType"
                  value="RSA_2048"
                  checked={keyType === 'RSA_2048'}
                  onChange={() => setKeyType('RSA_2048')}
                />
                <span className="ml-2 text-sm font-medium">RSA 2048</span>
              </label>
              <label className="flex items-center p-3 border rounded-lg cursor-pointer hover:bg-slate-50 transition-colors">
                <input
                  type="radio"
                  className="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 focus:ring-blue-500"
                  name="keyType"
                  value="RSA_4096"
                  checked={keyType === 'RSA_4096'}
                  onChange={() => setKeyType('RSA_4096')}
                />
                <span className="ml-2 text-sm font-medium">RSA 4096</span>
              </label>
            </div>
            <p className="text-sm text-slate-500 mt-2">Select the algorithm that matches your private key</p>
          </div>

          <button
            type="submit"
            disabled={isLoading}
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
                Sign & Get Certificate
              </>
            )}
          </button>
        </form>

        {status && (
          <div className={`mt-6 p-4 rounded-lg text-center ${
            status.includes('✅') 
              ? 'bg-green-50 border border-green-200 text-green-800' 
              : status.includes('❌')
              ? 'bg-red-50 border border-red-200 text-red-800'
              : 'bg-blue-50 border border-blue-200 text-blue-800'
          }`}>
            {status}
          </div>
        )}
      </div>

      {certificate && (
        <div className="card p-8 mt-8">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-2xl font-semibold text-slate-800 mb-2">Your Certificate</h2>
              <p className="text-slate-600">Digital certificate issued by the Certificate Authority</p>
            </div>
            <div className="w-12 h-12 bg-green-50 rounded-lg flex items-center justify-center">
              <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
          </div>
          
          <div className="bg-slate-50 rounded-lg p-4 mb-6 border">
            <pre className="text-sm font-mono text-slate-700 whitespace-pre-wrap break-all overflow-x-auto">
              {certificate}
            </pre>
          </div>
          
          <div className="flex flex-col sm:flex-row gap-3">
            <button
              onClick={() => copyToClipboard(certificate, 'Certificate copied to clipboard!')}
              className="btn btn-secondary flex-1"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
              </svg>
              Copy Certificate
            </button>
            {downloadUrl && (
              <a
                href={downloadUrl}
                download="certificate.pem"
                className="btn btn-primary flex-1"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Download Certificate
              </a>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
