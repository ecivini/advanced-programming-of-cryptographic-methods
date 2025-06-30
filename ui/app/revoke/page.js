'use client';

import React, { useState, useEffect } from 'react';
import { CA_URL } from '../utils/constants';
import { signMessage } from '../utils/crypto';
import { handleFileUpload } from '../utils/ui';
import { makeApiRequest } from '../utils/api';

export default function RevokePage() {
  const [serialNumber, setSerialNumber] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [revocationMessage, setRevocationMessage] = useState('');
  const [isRevoking, setIsRevoking] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  const privateKeyUploader = handleFileUpload(setPrivateKey);

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

  // Auto-generate revocation message when serial number changes
  useEffect(() => {
    if (serialNumber.trim()) {
      setRevocationMessage(`Revoke: ${serialNumber}`);
    } else {
      setRevocationMessage('');
    }
  }, [serialNumber]);

  // Revoke certificate
  const revokeCertificate = async () => {
    if (!serialNumber.trim() || !privateKey.trim() || !revocationMessage.trim()) {
      setError('Please provide a serial number, your private key, and a revocation message');
      return;
    }

    setIsRevoking(true);
    setError(null);
    setSuccess(false);

    try {
      // Sign the revocation message
      const signature = await signMessage(privateKey, revocationMessage);

      // Send revocation request to CA
      await makeApiRequest(`${CA_URL}/v1/certificate/revoke`, {
        signature: signature,
        serial_number: serialNumber,
      }, 'POST', true); // expect JSON response

      setSuccess(true);
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
      {/* Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-12 h-12 bg-gradient-to-r from-red-500 to-red-600 rounded-2xl mb-4">
          <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.728-.833-2.498 0L4.316 16.5c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
        </div>
        <h1 className="text-3xl font-bold text-slate-800 mb-2">Revoke Certificate</h1>
        <p className="text-slate-600">Sign a message to revoke a certificate from the Certificate Authority</p>
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
            <h2 className="text-2xl font-bold text-slate-800 mb-2">Certificate Revoked Successfully</h2>
            <p className="text-slate-600 mb-6">The certificate has been revoked and added to the Certificate Revocation List (CRL)</p>
            <div className="flex gap-4 justify-center">
              <button
                onClick={() => {
                  setSuccess(false);
                  setSerialNumber('');
                  setPrivateKey('');
                  setRevocationMessage('');
                  setError(null);
                }}
                className="btn btn-primary"
              >
                Revoke Another Certificate
              </button>
              <button
                onClick={() => window.location.href = '/crl'}
                className="btn btn-secondary"
              >
                View CRL
              </button>
            </div>
          </div>
        </div>
      ) : (
        // Revocation form
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
                disabled={isRevoking}
              />
              <p className="text-sm text-slate-500 mt-2">
                Enter the full serial number of the certificate you want to revoke.
              </p>
            </div>

            {/* Show auto-generated message */}
            {revocationMessage && (
              <div className="bg-blue-50 border border-blue-200 p-4 rounded-lg">
                <label className="text-sm font-medium text-blue-800 block mb-2">Auto-generated Message to Sign</label>
                <p className="text-blue-700 font-mono text-sm break-all bg-white p-2 rounded border">
                  {revocationMessage}
                </p>
                <p className="text-xs text-blue-600 mt-2">
                  This message will be signed with your private key to authorize the revocation.
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
                    onChange={privateKeyUploader}
                    className="hidden"
                    id="privateKeyFileInput"
                    disabled={isRevoking}
                  />
                  <label
                    htmlFor="privateKeyFileInput"
                    className={`btn btn-secondary cursor-pointer ${isRevoking ? 'opacity-50 cursor-not-allowed' : ''}`}
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1721 9z" />
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
            
            {/* Submit Button */}
            <button
              onClick={revokeCertificate}
              disabled={isRevoking || !privateKey.trim() || !revocationMessage.trim() || !serialNumber.trim()}
              className={`btn btn-danger w-full ${
                isRevoking || !privateKey.trim() || !revocationMessage.trim() || !serialNumber.trim() ? 'opacity-50 cursor-not-allowed' : ''
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
        </div>
      )}
    </div>
  );
}
