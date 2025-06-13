'use client';

import { useState } from 'react';

export default function SignPage() {
  const [challenge, setChallenge] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [certificate, setCertificate] = useState('');

  const handleFileUpload = (event, setter) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setter(e.target.result);
      };
      reader.readAsText(file);
    }
  };

  const detectKeyType = (pemContent) => {
    // Check for PKCS#8 format (modern standard)
    if (pemContent.includes('BEGIN PRIVATE KEY')) {
      // For PKCS#8, we need to parse the content to determine the algorithm
      // This is a simplified detection - in practice, we'd parse the ASN.1
      const b64Content = pemContent
        .replace(/-----[^-]+-----/g, '')
        .replace(/\s+/g, '');
      const byteLength = (b64Content.length * 3) / 4;
      
      // ECDSA P-256 keys are typically smaller
      if (byteLength < 200) {
        return 'ECDSA';
      }
      // Larger keys are likely RSA
      if (byteLength > 2000) {
        return 'RSA_4096';
      }
      return 'RSA_2048';
    }
    
    // Traditional formats (not supported by Web Crypto API directly)
    if (pemContent.includes('BEGIN EC PRIVATE KEY')) {
      return 'ECDSA';
    }
    if (pemContent.includes('BEGIN RSA PRIVATE KEY')) {
      const base64Content = pemContent
        .replace(/-----[^-]+-----/g, '')
        .replace(/\s+/g, '');
      const byteLength = (base64Content.length * 3) / 4;
      
      if (byteLength > 2000) {
        return 'RSA_4096';
      }
      return 'RSA_2048';
    }
    
    return 'ECDSA'; // Default fallback
  };

  const importPrivateKey = async (pemContent) => {
    try {
      const keyType = detectKeyType(pemContent);
      
      // For Web Crypto API, we only support PKCS#8 format
      // Traditional formats need to be converted first
      if (pemContent.includes('BEGIN RSA PRIVATE KEY') || pemContent.includes('BEGIN EC PRIVATE KEY')) {
        throw new Error('Traditional PEM formats (PKCS#1/SEC1) are not directly supported. Please convert to PKCS#8 format using: openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private_key.pem -out private_key_pkcs8.pem');
      }
      
      // Clean up PKCS#8 PEM content
      let b64Content = pemContent
        .replace(/-----BEGIN PRIVATE KEY-----/, '')
        .replace(/-----END PRIVATE KEY-----/, '')
        .replace(/\s+/g, '');

      const binaryData = Uint8Array.from(atob(b64Content), c => c.charCodeAt(0));

      let keyParams;

      if (keyType === 'ECDSA') {
        keyParams = {
          name: 'ECDSA',
          namedCurve: 'P-256'
        };
      } else {
        keyParams = {
          name: 'RSASSA-PKCS1-v1_5',
          hash: 'SHA-256'
        };
      }

      return await crypto.subtle.importKey(
        'pkcs8',
        binaryData.buffer,
        keyParams,
        false,
        ['sign']
      );
    } catch (error) {
      console.error('Key import error:', error);
      throw new Error(`Failed to import private key: ${error.message}`);
    }
  };

  const signChallenge = async (privateKey, challengeData) => {
    try {
      const keyType = detectKeyType(privateKey);
      const key = await importPrivateKey(privateKey);
      
      // Use challenge data as-is (base64 string) - convert to bytes for signing
      const challengeBytes = new TextEncoder().encode(challengeData);
      
      console.log('Challenge data:', challengeData);
      console.log('Challenge bytes length:', challengeBytes.length);
      console.log('Key type:', keyType);
      
      let signatureBuffer;
      if (keyType === 'ECDSA') {
        signatureBuffer = await crypto.subtle.sign(
          {
            name: 'ECDSA',
            hash: { name: 'SHA-256' }
          },
          key,
          challengeBytes
        );
        
        // Convert ECDSA signature from IEEE P1363 format to ASN.1 DER format
        const signature = new Uint8Array(signatureBuffer);
        const r = signature.slice(0, 32);
        const s = signature.slice(32, 64);
        
        // Create ASN.1 DER encoded signature
        const derSignature = encodeECDSASignatureToDER(r, s);
        return btoa(String.fromCharCode(...derSignature));
      } else {
        // For RSA, use RSASSA-PKCS1-v1_5 with SHA-256
        signatureBuffer = await crypto.subtle.sign(
          {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256'
          },
          key,
          challengeBytes
        );
        
        const signature = new Uint8Array(signatureBuffer);
        console.log('RSA signature length:', signature.length);
        console.log('RSA signature (first 20 bytes):', Array.from(signature.slice(0, 20)).map(b => b.toString(16).padStart(2, '0')).join(' '));
        
        return btoa(String.fromCharCode(...signature));
      }
    } catch (error) {
      console.error('Signing error:', error);
      throw new Error(`Failed to sign challenge: ${error.message}`);
    }
  };

  // Helper function to encode ECDSA signature to DER format
  const encodeECDSASignatureToDER = (r, s) => {
    const encodeInteger = (int) => {
      // Remove leading zeros
      let start = 0;
      while (start < int.length && int[start] === 0) start++;
      if (start === int.length) return new Uint8Array([0]);
      
      const trimmed = int.slice(start);
      
      // Add padding if first bit is 1 (negative in two's complement)
      if (trimmed[0] & 0x80) {
        const padded = new Uint8Array(trimmed.length + 1);
        padded[0] = 0;
        padded.set(trimmed, 1);
        return padded;
      }
      
      return trimmed;
    };

    const rEncoded = encodeInteger(r);
    const sEncoded = encodeInteger(s);

    // Build DER sequence
    const rTLV = new Uint8Array([0x02, rEncoded.length, ...rEncoded]);
    const sTLV = new Uint8Array([0x02, sEncoded.length, ...sEncoded]);
    
    const sequenceContent = new Uint8Array([...rTLV, ...sTLV]);
    return new Uint8Array([0x30, sequenceContent.length, ...sequenceContent]);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!challenge.trim()) {
      setError('Please enter the challenge code');
      return;
    }
    
    if (!privateKey.trim()) {
      setError('Please paste your private key');
      return;
    }

    setLoading(true);
    setError('');
    setSuccess('');
    setCertificate('');

    try {
      // Sign the challenge
      setSuccess('Signing challenge...');
      const signature = await signChallenge(privateKey, challenge);
      
      console.log('Frontend signing details:');
      console.log('Challenge:', challenge);
      console.log('Challenge length:', challenge.length);
      console.log('Signature base64:', signature);
      console.log('Signature base64 length:', signature.length);
      
      // Request certificate
      setSuccess('Requesting certificate...');
      const caUrl = process.env.NEXT_PUBLIC_CA_URL || 'http://localhost:5000';
      const response = await fetch(`${caUrl}/v1/certificate`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          signature: signature,
          challenge: challenge
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setCertificate(data.certificate);
      setSuccess('Certificate generated successfully! You can now download it.');
      
    } catch (err) {
      console.error('Certificate request failed:', err);
      setError(err.message || 'Failed to generate certificate');
    } finally {
      setLoading(false);
    }
  };

  const downloadCertificate = () => {
    if (!certificate) return;
    
    const blob = new Blob([certificate], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'certificate.pem';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      setSuccess('Copied to clipboard!');
      setTimeout(() => setSuccess(''), 2000);
    });
  };

  return (
    <div className="max-w-4xl mx-auto">
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-12 h-12 bg-gradient-to-r from-blue-500 to-blue-600 rounded-2xl mb-4">
          <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <h1 className="text-3xl font-bold text-slate-800 mb-2">Sign Certificate</h1>
        <p className="text-slate-600">Sign your challenge and request your certificate</p>
      </div>

      <div className="card p-8">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label htmlFor="challenge" className="label">
              Challenge Code
            </label>
            <textarea
              id="challenge"
              value={challenge}
              onChange={(e) => setChallenge(e.target.value)}
              placeholder="Paste the challenge code you received via email"
              className="input font-mono resize-none"
              rows={3}
              disabled={loading}
              required
            />
            <p className="text-sm text-slate-500 mt-2">
              Enter the base64-encoded challenge from your email
            </p>
          </div>

          <div>
            <label htmlFor="privateKey" className="label">
              Private Key
            </label>
            <div className="space-y-3">
              <div className="flex gap-2">
                <input
                  type="file"
                  accept=".pem,.key"
                  onChange={(e) => handleFileUpload(e, setPrivateKey)}
                  disabled={loading}
                  className="hidden"
                  id="privateKeyFileInput"
                />
                <label
                  htmlFor="privateKeyFileInput"
                  className="btn btn-secondary cursor-pointer"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  Upload Private Key
                </label>
                <span className="text-sm text-slate-500 self-center">or paste below</span>
              </div>
              <textarea
                id="privateKey"
                value={privateKey}
                onChange={(e) => setPrivateKey(e.target.value)}
                placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                className="input font-mono resize-none"
                rows={8}
                disabled={loading}
                required
              />
            </div>
            <div className="mt-3 p-4 bg-blue-50 border border-blue-200 rounded-lg">
              <div className="text-sm text-blue-800">
                <p className="font-medium mb-2">📋 Private Key Requirements:</p>
                <ul className="space-y-1 ml-4">
                  <li>• Must be in <strong>PKCS#8 format</strong></li>
                  <li>• Should start with <code className="text-xs bg-blue-100 px-1 rounded">-----BEGIN PRIVATE KEY-----</code></li>
                  <li>• Supports ECDSA P-256, RSA 2048/4096</li>
                </ul>
                
                <div className="mt-3 p-3 bg-blue-100 rounded border-l-4 border-blue-400">
                  <p className="font-medium mb-2">🔧 Key Format Conversion</p>
                  <p className="mb-2">If you have a traditional format key, convert using OpenSSL:</p>
                  <div className="space-y-2 font-mono text-xs">
                    <div className="bg-blue-200 p-2 rounded">
                      <strong>For RSA keys:</strong><br/>
                      <code>openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in rsa_key.pem -out private_key.pem</code>
                    </div>
                    <div className="bg-blue-200 p-2 rounded">
                      <strong>For EC keys:</strong><br/>
                      <code>openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in ec_key.pem -out private_key.pem</code>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <div className="flex items-center text-red-800">
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {error}
              </div>
            </div>
          )}

          {success && !certificate && (
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <div className="flex items-center text-blue-800">
                <svg className="w-5 h-5 mr-2 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                {success}
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={loading || !challenge.trim() || !privateKey.trim()}
            className={`btn btn-primary w-full ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {loading ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                Processing...
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                Sign & Request Certificate
              </>
            )}
          </button>
        </form>

        {certificate && (
          <div className="mt-8 border-t border-slate-200 pt-8">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h3 className="text-xl font-semibold text-slate-800 mb-2">Your Certificate</h3>
                <p className="text-slate-600">Certificate generated successfully!</p>
              </div>
              <div className="w-10 h-10 bg-green-50 rounded-lg flex items-center justify-center">
                <svg className="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
            </div>
            
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 mb-4">
              <pre className="text-xs text-slate-700 font-mono whitespace-pre-wrap break-all max-h-96 overflow-y-auto">{certificate}</pre>
            </div>
            
            <div className="flex gap-3">
              <button
                onClick={downloadCertificate}
                className="btn btn-primary"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Download Certificate
              </button>
              <button
                onClick={() => copyToClipboard(certificate)}
                className="btn btn-secondary"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
                Copy to Clipboard
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="mt-8 card p-8">
        <div className="text-center mb-6">
          <div className="w-12 h-12 bg-blue-50 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h3 className="text-xl font-semibold text-slate-800 mb-2">How it works</h3>
          <p className="text-slate-600">Follow these steps to get your certificate</p>
        </div>
        
        <div className="grid md:grid-cols-3 gap-6">
          <div className="text-center">
            <div className="w-10 h-10 bg-green-100 text-green-600 rounded-full flex items-center justify-center mx-auto mb-4 font-semibold">
              1
            </div>
            <h4 className="font-semibold text-slate-800 mb-2">Commit Identity</h4>
            <p className="text-sm text-slate-600">First, commit your identity with your public key on the commit page</p>
          </div>
          <div className="text-center">
            <div className="w-10 h-10 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center mx-auto mb-4 font-semibold">
              2
            </div>
            <h4 className="font-semibold text-slate-800 mb-2">Receive Challenge</h4>
            <p className="text-sm text-slate-600">Check your email for the challenge code</p>
          </div>
          <div className="text-center">
            <div className="w-10 h-10 bg-purple-100 text-purple-600 rounded-full flex items-center justify-center mx-auto mb-4 font-semibold">
              3
            </div>
            <h4 className="font-semibold text-slate-800 mb-2">Sign Challenge</h4>
            <p className="text-sm text-slate-600">Use your private key to sign the challenge and request your certificate</p>
          </div>
        </div>
      </div>
    </div>
  );
}