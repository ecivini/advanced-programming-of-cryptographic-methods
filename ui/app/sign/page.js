'use client';

import React, { useState } from 'react';
import { CA_URL } from '../utils/constants';
import { signChallenge } from '../utils/crypto';
import { handleFileUpload } from '../utils/ui';
import { makeApiRequest, parseErrorResponse } from '../utils/api';

export default function SignPage() {
  const [challenge, setChallenge] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [status, setStatus] = useState(null);
  const [certificate, setCertificate] = useState('');

  const privateKeyUploader = handleFileUpload(setPrivateKey);

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
      const response = await makeApiRequest(`${CA_URL}/v1/certificate`, {
        signature: signature, 
        challenge: challengeTrimmed 
      }, 'PUT', false); // expect text response (PEM certificate)

      // The API function now returns the certificate text directly
      setCertificate(response);
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
                  onChange={privateKeyUploader}
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
