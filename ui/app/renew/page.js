'use client';

import React, { useState, useEffect } from 'react';
import { signMessage } from '../utils/crypto';
import { handleFileUpload, downloadTextFile } from '../utils/ui';
import { makeApiRequest } from '../utils/api';

export default function RenewPage() {
  const [serialNumber, setSerialNumber] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [renewalMessage, setRenewalMessage] = useState('');
  const [isRenewing, setIsRenewing] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);
  const [newCertificate, setNewCertificate] = useState('');

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

  // Auto-generate renewal message when serial number changes
  useEffect(() => {
    if (serialNumber.trim()) {
      setRenewalMessage(`Renew: ${serialNumber}`);
    } else {
      setRenewalMessage('');
    }
  }, [serialNumber]);

  // Renew certificate
  const renewCertificate = async () => {
    if (!serialNumber.trim() || !privateKey.trim() || !renewalMessage.trim()) {
      setError('Please provide a serial number, your private key, and a renewal message');
      return;
    }

    setIsRenewing(true);
    setError(null);
    setSuccess(false);

    try {
      // Sign the renewal message
      const signature = await signMessage(privateKey, renewalMessage);

      // Send renewal request to CA
      const CA_URL = process.env.NEXT_PUBLIC_CA_URL || 'http://localhost:5000';
      const result = await makeApiRequest(CA_URL + '/v1/cert/renew', {
        signature: signature,
        serial_number: serialNumber,
      }, 'POST', true); // expect JSON response

      setNewCertificate(result.certificate);
      setSuccess(true);
      setError('✅ Certificate renewed successfully!');
    } catch (error) {
      console.error('Certificate renewal error:', error);
      setError(`❌ Renewal failed: ${error.message}`);
    } finally {
      setIsRenewing(false);
    }
  };

  // Download certificate using shared utility
  const downloadCertificate = () => {
    downloadTextFile(newCertificate, `renewed-certificate-${serialNumber}.pem`, 'application/x-pem-file');
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-12 h-12 bg-gradient-to-r from-blue-500 to-blue-600 rounded-2xl mb-4">
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
        // Success message with new certificate
        <div className="card p-6">
          <div className="text-center mb-6">
            <div className="inline-flex items-center justify-center w-12 h-12 bg-gradient-to-r from-green-500 to-green-600 rounded-2xl mb-4">
              <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h2 className="text-2xl font-bold text-slate-800 mb-2">Certificate Renewed Successfully</h2>
            <p className="text-slate-600 mb-6">Your certificate has been renewed with a new validity period</p>
          </div>

          {/* New Certificate Display */}
          <div className="mb-6">
            <div className="flex justify-between items-center mb-3">
              <h3 className="text-lg font-semibold text-slate-800">New Certificate</h3>
              <button
                onClick={downloadCertificate}
                className="btn btn-primary"
              >
                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Download Certificate
              </button>
            </div>
            <div className="bg-slate-50 border rounded-lg p-4">
              <pre className="text-sm font-mono text-slate-700 whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                {newCertificate}
              </pre>
            </div>
          </div>

          <div className="flex gap-4 justify-center">
            <button
              onClick={() => {
                setSuccess(false);
                setSerialNumber('');
                setPrivateKey('');
                setRenewalMessage('');
                setNewCertificate('');
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

            {/* Show auto-generated message */}
            {renewalMessage && (
              <div className="bg-blue-50 border border-blue-200 p-4 rounded-lg">
                <label className="text-sm font-medium text-blue-800 block mb-2">Auto-generated Message to Sign</label>
                <p className="text-blue-700 font-mono text-sm break-all bg-white p-2 rounded border">
                  {renewalMessage}
                </p>
                <p className="text-xs text-blue-600 mt-2">
                  This message will be signed with your private key to authorize the renewal.
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
                    disabled={isRenewing}
                  />
                  <label
                    htmlFor="privateKeyFileInput"
                    className={`btn btn-secondary cursor-pointer ${isRenewing ? 'opacity-50 cursor-not-allowed' : ''}`}
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
              disabled={isRenewing || !privateKey.trim() || !renewalMessage.trim() || !serialNumber.trim()}
              className={`btn btn-primary w-full ${
                isRenewing || !privateKey.trim() || !renewalMessage.trim() || !serialNumber.trim() ? 'opacity-50 cursor-not-allowed' : ''
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
