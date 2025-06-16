'use client';

import React, { useState } from 'react';

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

// Parse ASN.1/DER certificate to extract serial number
function parseSerialNumber(certificatePEM) {
  try {
    const lines = certificatePEM.split('\n');
    const base64Data = lines
      .filter(line => !line.startsWith('-----'))
      .join('')
      .replace(/\s/g, '');
    
    const binaryData = Uint8Array.from(atob(base64Data), c => c.charCodeAt(0));
    
    // Simple ASN.1 parsing to find serial number
    // This is a basic implementation - a full ASN.1 parser would be more robust
    let offset = 0;
    
    // Skip outer SEQUENCE
    if (binaryData[offset] !== 0x30) throw new Error('Invalid certificate format');
    offset++;
    
    // Skip length
    if (binaryData[offset] & 0x80) {
      const lengthBytes = binaryData[offset] & 0x7f;
      offset += lengthBytes + 1;
    } else {
      offset++;
    }
    
    // Skip tbsCertificate SEQUENCE
    if (binaryData[offset] !== 0x30) throw new Error('Invalid tbsCertificate format');
    offset++;
    
    // Skip length
    if (binaryData[offset] & 0x80) {
      const lengthBytes = binaryData[offset] & 0x7f;
      offset += lengthBytes + 1;
    } else {
      offset++;
    }
    
    // Skip version (optional, context-specific [0])
    if (binaryData[offset] === 0xa0) {
      offset++;
      // Skip length
      if (binaryData[offset] & 0x80) {
        const lengthBytes = binaryData[offset] & 0x7f;
        offset += lengthBytes + 1;
      } else {
        offset++;
      }
      // Skip version value
      offset += 3; // Usually [02 01 02] for version 3
    }
    
    // Now we should be at the serial number
    if (binaryData[offset] !== 0x02) throw new Error('Serial number not found');
    offset++;
    
    const serialLength = binaryData[offset];
    offset++;
    
    const serialBytes = binaryData.slice(offset, offset + serialLength);
    
    // Convert to decimal string
    let serialNumber = '';
    for (let i = 0; i < serialBytes.length; i++) {
      if (i === 0 && serialBytes[i] === 0) continue; // Skip leading zero
      serialNumber = (BigInt(serialNumber || '0') * BigInt(256) + BigInt(serialBytes[i])).toString();
    }
    
    return serialNumber || '0';
  } catch (error) {
    console.warn('Failed to parse serial number:', error);
    return null;
  }
}

export default function CertsPage() {
  const [certificatePEM, setCertificatePEM] = useState('');
  const [certificateInfo, setCertificateInfo] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [privateKey, setPrivateKey] = useState('');
  const [isRevoking, setIsRevoking] = useState(false);
  const [revocationSuccess, setRevocationSuccess] = useState(false);
  const [revocationMessage, setRevocationMessage] = useState('');

  // Handle file upload for certificate
  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setCertificatePEM(e.target.result);
      };
      reader.readAsText(file);
    }
  };

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

  // Check if certificate is revoked by querying certificate status
  const checkRevocationStatus = async (serialNumber) => {
    try {
      // Query certificate status API to check if certificate is revoked
      const certURL = `${process.env.NEXT_PUBLIC_CA_URL}/v1/certificate/${serialNumber}/status`;
      const res = await fetch(certURL);
      
      if (!res.ok) {
        // If certificate not found or other error, assume it's active (not revoked)
        console.warn('Cannot check certificate status:', res.status);
        return { isRevoked: false, revocationDate: null, error: null };
      }
      
      const statusData = await res.json();
      
      // Check if the certificate has revocation flag set
      return { 
        isRevoked: statusData.revoked || false, 
        revocationDate: statusData.revocation_date || null,
        error: null 
      };
    } catch (error) {
      // If there's an error, assume certificate is active (not revoked)
      console.warn('Error checking certificate status:', error);
      return { isRevoked: false, revocationDate: null, error: null };
    }
  };

  // Parse certificate information
  const parseCertificate = async () => {
    if (!certificatePEM.trim()) {
      setError('Please provide a certificate');
      return;
    }

    setIsLoading(true);
    setError(null);
    setCertificateInfo(null);
    setRevocationSuccess(false);

    try {
      const lines = certificatePEM.split('\n');
      const base64Data = lines
        .filter(line => !line.startsWith('-----'))
        .join('')
        .replace(/\s/g, '');

      const serialNumber = parseSerialNumber(certificatePEM);
      
      // Check if certificate format is valid
      const hasValidFormat = certificatePEM.includes('-----BEGIN CERTIFICATE-----') && 
                           certificatePEM.includes('-----END CERTIFICATE-----');

      let revocationStatus = { isRevoked: false, revocationDate: null, error: null };
      
      // Only check revocation status if we have a serial number and valid format
      if (serialNumber && hasValidFormat) {
        revocationStatus = await checkRevocationStatus(serialNumber);
      }

      const info = {
        format: 'X.509',
        encoding: 'PEM',
        size: base64Data.length,
        lines: lines.length,
        hasBeginMarker: certificatePEM.includes('-----BEGIN CERTIFICATE-----'),
        hasEndMarker: certificatePEM.includes('-----END CERTIFICATE-----'),
        hasValidFormat: hasValidFormat,
        serialNumber: serialNumber,
        isRevoked: revocationStatus.isRevoked,
        revocationDate: revocationStatus.revocationDate,
        // Certificate is valid if it has correct format AND is not revoked
        isValid: hasValidFormat && !revocationStatus.isRevoked
      };

      setCertificateInfo(info);
      
      // Do not auto-populate revocation message - let user enter it manually
    } catch (err) {
      setError(`Failed to parse certificate: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Copy to clipboard
  const copyToClipboard = async (text, successMessage = 'Copied to clipboard') => {
    try {
      await navigator.clipboard.writeText(text);
      setError(null);
      // Show success feedback briefly
      const originalError = error;
      setError(`✅ ${successMessage}`);
      setTimeout(() => setError(originalError), 2000);
    } catch (err) {
      setError(`Failed to copy: ${err.message}`);
    }
  };

  // Format serial number for display (first 5 and last 5 digits with ellipsis)
  const formatSerialNumber = (serialNumber) => {
    if (!serialNumber || serialNumber.length <= 10) {
      return serialNumber;
    }
    return `${serialNumber.slice(0, 5)}...${serialNumber.slice(-5)}`;
  };

  // Revoke certificate
  const revokeCertificate = async () => {
    if (!certificateInfo || !certificateInfo.serialNumber || !privateKey.trim() || !revocationMessage.trim()) {
      setError('Please provide a valid certificate, your private key, and a revocation message');
      return;
    }

    setIsRevoking(true);
    setError(null);
    setRevocationSuccess(false);

    try {
      // Sign the revocation message
      const signature = await signMessage(privateKey, revocationMessage);

      // Send revocation request to CA
      const response = await fetch(`${CA_URL}/v1/certificate/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          serial_number: certificateInfo.serialNumber,
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
        throw new Error(errorMessage || `Revocation failed: HTTP ${response.status}`);
      }

      setRevocationSuccess(true);
      setError('✅ Certificate revoked successfully!');
    } catch (error) {
      console.error('Certificate revocation error:', error);
      setError(`❌ Revocation failed: ${error.message}`);
    } finally {
      setIsRevoking(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-12 h-12 bg-gradient-to-r from-purple-500 to-purple-600 rounded-2xl mb-4">
          <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
        </div>
        <h1 className="text-3xl font-bold text-slate-800 mb-2">Certificate Viewer</h1>
        <p className="text-slate-600">View and analyze X.509 digital certificates</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Certificate Input */}
        <div className="card p-6">
          <h2 className="text-xl font-semibold text-slate-800 mb-4">Certificate Input</h2>
          
          <div className="space-y-4">
            <div className="flex gap-2">
              <input
                type="file"
                accept=".pem,.crt,.cer,.txt"
                onChange={handleFileUpload}
                className="hidden"
                id="certFileInput"
              />
              <label
                htmlFor="certFileInput"
                className="btn btn-secondary cursor-pointer"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Upload Certificate
              </label>
              <span className="text-sm text-slate-500 self-center">or paste below</span>
            </div>
            
            <textarea
              rows={12}
              className="input font-mono resize-none"
              placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
              value={certificatePEM}
              onChange={e => setCertificatePEM(e.target.value)}
            />
            
            <div className="flex gap-3">
              <button
                onClick={parseCertificate}
                disabled={isLoading || !certificatePEM.trim()}
                className={`btn btn-primary flex-1 ${
                  isLoading || !certificatePEM.trim() ? 'opacity-50 cursor-not-allowed' : ''
                }`}
              >
                {isLoading ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                    Parsing...
                  </>
                ) : (
                  <>
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                    Parse Certificate
                  </>
                )}
              </button>
              
              {certificatePEM && (
                <button
                  onClick={() => copyToClipboard(certificatePEM, 'Certificate copied!')}
                  className="btn btn-secondary"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Certificate Information */}
        <div className="card p-6">
          <h2 className="text-xl font-semibold text-slate-800 mb-4">Certificate Information</h2>
          
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-800 p-4 rounded-lg mb-4">
              <div className="flex items-center">
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {error}
              </div>
            </div>
          )}

          {!certificateInfo && !error && !isLoading && (
            <div className="text-center py-12 text-slate-500">
              <svg className="w-12 h-12 mx-auto mb-4 text-slate-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              <p>Upload or paste a certificate to view its information</p>
            </div>
          )}

          {certificateInfo && (
            <div className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-50 p-3 rounded-lg">
                  <label className="text-sm font-medium text-slate-600">Format</label>
                  <p className="text-slate-800 font-mono">{certificateInfo.format}</p>
                </div>
                <div className="bg-slate-50 p-3 rounded-lg">
                  <label className="text-sm font-medium text-slate-600">Encoding</label>
                  <p className="text-slate-800 font-mono">{certificateInfo.encoding}</p>
                </div>
                <div className="bg-slate-50 p-3 rounded-lg">
                  <label className="text-sm font-medium text-slate-600">Data Size</label>
                  <p className="text-slate-800 font-mono">{certificateInfo.size} bytes</p>
                </div>
                <div className="bg-slate-50 p-3 rounded-lg">
                  <label className="text-sm font-medium text-slate-600">Status</label>
                  <div className="flex items-center">
                    {!certificateInfo.hasValidFormat ? (
                      <>
                        <div className="w-2 h-2 bg-red-500 rounded-full mr-2"></div>
                        <span className="text-red-700 text-sm font-medium">Invalid Format</span>
                      </>
                    ) : certificateInfo.isRevoked ? (
                      <>
                        <div className="w-2 h-2 bg-red-500 rounded-full mr-2"></div>
                        <span className="text-red-700 text-sm font-medium">Revoked</span>
                      </>
                    ) : (
                      <>
                        <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                        <span className="text-green-700 text-sm font-medium">Active</span>
                      </>
                    )}
                  </div>
                  {certificateInfo.isRevoked && certificateInfo.revocationDate && (
                    <p className="text-xs text-slate-500 mt-1">
                      Revoked: {new Date(certificateInfo.revocationDate).toLocaleString()}
                    </p>
                  )}
                </div>
              </div>

              {/* Serial Number Display */}
              {certificateInfo.serialNumber && (
                <div className="bg-slate-50 p-4 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-sm font-medium text-slate-600">Serial Number</label>
                    <button
                      onClick={() => copyToClipboard(certificateInfo.serialNumber, 'Serial number copied!')}
                      className="btn btn-secondary text-xs"
                      title="Copy full serial number"
                    >
                      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                      Copy Full
                    </button>
                  </div>
                  <p className="text-slate-800 font-mono text-sm break-all">
                    {formatSerialNumber(certificateInfo.serialNumber)}
                  </p>
                </div>
              )}

              <div className="bg-blue-50 border border-blue-200 p-4 rounded-lg">
                <h3 className="text-sm font-medium text-blue-800 mb-2">Format Validation</h3>
                <div className="space-y-1 text-sm">
                  <div className="flex items-center">
                    {certificateInfo.hasBeginMarker ? (
                      <svg className="w-4 h-4 text-green-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                    ) : (
                      <svg className="w-4 h-4 text-red-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    )}
                    <span className="text-blue-700">BEGIN CERTIFICATE marker</span>
                  </div>
                  <div className="flex items-center">
                    {certificateInfo.hasEndMarker ? (
                      <svg className="w-4 h-4 text-green-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                    ) : (
                      <svg className="w-4 h-4 text-red-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    )}
                    <span className="text-blue-700">END CERTIFICATE marker</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Certificate Revocation Section */}
      {certificateInfo && certificateInfo.hasValidFormat && certificateInfo.serialNumber && !revocationSuccess && (
        <div className="card p-6">
          {certificateInfo.isRevoked ? (
            // Certificate is already revoked - show info message
            <div className="text-center py-8">
              <div className="inline-flex items-center justify-center w-12 h-12 bg-red-100 rounded-2xl mb-4">
                <svg className="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.728-.833-2.498 0L4.316 16.5c-.77.833.192 2.5 1.732 2.5z" />
                </svg>
              </div>
              <h2 className="text-xl font-bold text-slate-800 mb-2">Certificate Already Revoked</h2>
              <p className="text-slate-600 mb-1">This certificate has already been revoked by the Certificate Authority.</p>
              {certificateInfo.revocationDate && (
                <p className="text-sm text-slate-500">
                  Revocation Date: {new Date(certificateInfo.revocationDate).toLocaleString()}
                </p>
              )}
            </div>
          ) : (
            // Show revocation form for active certificates
            <>
              <div className="text-center mb-6">
                <div className="inline-flex items-center justify-center w-10 h-10 bg-gradient-to-r from-red-500 to-red-600 rounded-2xl mb-4">
                  <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.728-.833-2.498 0L4.316 16.5c-.77.833.192 2.5 1.732 2.5z" />
                  </svg>
                </div>
                <h2 className="text-2xl font-bold text-slate-800 mb-2">Revoke Certificate</h2>
                <p className="text-slate-600">Sign a message to revoke this certificate from the Certificate Authority</p>
              </div>

          <div className="max-w-2xl mx-auto space-y-6">
            <div className="bg-red-50 border border-red-200 p-4 rounded-lg">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <p className="text-sm text-red-700 mb-2">
                    <strong>Quick Revocation Helper</strong>
                  </p>
                  <p className="text-sm text-red-700 mb-3">
                    To revoke this certificate click the button to auto-populate the message field.
                    You can then sign the message with your private key."
                  </p>
                </div>
                <button
                  onClick={() => setRevocationMessage(`Revoke:${certificateInfo.serialNumber}`)}
                  className="btn btn-secondary text-xs ml-4 flex-shrink-0"
                  title="Auto-populate revocation message"
                >
                  <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  Auto-fill Message
                </button>
              </div>
            </div>

            <div>
              <label className="label">Message to Sign</label>
              <textarea
                rows={3}
                className="input font-mono resize-none"
                placeholder="Revoke:"
                value={revocationMessage}
                onChange={(e) => setRevocationMessage(e.target.value)}
                disabled={isRevoking}
              />
              <p className="text-sm text-slate-500 mt-2">
                Enter the message to sign. Format: "Revoke:&lt;serial_number&gt;" (copy the serial number from above)
              </p>
            </div>

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
                    disabled={isRevoking}
                  />
                  <label
                    htmlFor="privateKeyFileInput"
                    className={`btn btn-secondary cursor-pointer ${isRevoking ? 'opacity-50 cursor-not-allowed' : ''}`}
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
                  disabled={isRevoking}
                />
              </div>
              <p className="text-sm text-slate-500 mt-2">
                Your private key (PKCS#8, PKCS#1, or SEC1 format). Supports RSA and ECDSA keys.
              </p>
            </div>
            
            <button
              onClick={revokeCertificate}
              disabled={isRevoking || !privateKey.trim() || !revocationMessage.trim()}
              className={`btn btn-danger w-full ${
                isRevoking || !privateKey.trim() || !revocationMessage.trim() ? 'opacity-50 cursor-not-allowed' : ''
              }`}
            >
              {isRevoking ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                  Revoking Certificate...
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                  Sign Message & Revoke Certificate
                </>
              )}
            </button>
          </div>
            </>
          )}
        </div>
      )}

      {/* Success message for revocation */}
      {revocationSuccess && (
        <div className="card p-6">
          <div className="text-center">
            <div className="inline-flex items-center justify-center w-12 h-12 bg-gradient-to-r from-green-500 to-green-600 rounded-2xl mb-4">
              <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h2 className="text-2xl font-bold text-slate-800 mb-2">Certificate Revoked Successfully</h2>
            <p className="text-slate-600">The certificate has been revoked and added to the Certificate Revocation List (CRL)</p>
            <div className="mt-6">
              <button
                onClick={() => {
                  setRevocationSuccess(false);
                  setCertificateInfo(null);
                  setCertificatePEM('');
                  setPrivateKey('');
                  setRevocationMessage('');
                }}
                className="btn btn-primary"
              >
                Revoke Another Certificate
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
