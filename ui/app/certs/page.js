'use client';

import React, { useState } from 'react';

export default function CertsPage() {
  const [certificatePEM, setCertificatePEM] = useState('');
  const [certificateInfo, setCertificateInfo] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

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

  // Parse certificate information
  const parseCertificate = async () => {
    if (!certificatePEM.trim()) {
      setError('Please provide a certificate');
      return;
    }

    setIsLoading(true);
    setError(null);
    setCertificateInfo(null);

    try {
      // This is a simplified parser - in a real application you'd use a proper ASN.1/X.509 parser
      const lines = certificatePEM.split('\n');
      const base64Data = lines
        .filter(line => !line.startsWith('-----'))
        .join('')
        .replace(/\s/g, '');

      // For demonstration, we'll show basic info that can be extracted
      const info = {
        format: 'X.509',
        encoding: 'PEM',
        size: base64Data.length,
        lines: lines.length,
        hasBeginMarker: certificatePEM.includes('-----BEGIN CERTIFICATE-----'),
        hasEndMarker: certificatePEM.includes('-----END CERTIFICATE-----'),
        isValid: certificatePEM.includes('-----BEGIN CERTIFICATE-----') && 
                certificatePEM.includes('-----END CERTIFICATE-----')
      };

      setCertificateInfo(info);
    } catch (err) {
      setError(`Failed to parse certificate: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Copy to clipboard
  const copyToClipboard = async (text, successMessage) => {
    try {
      await navigator.clipboard.writeText(text);
      // Simple success indication - could be improved with toast notifications
      setError(null);
    } catch (err) {
      setError(`Failed to copy: ${err.message}`);
    }
  };

  return (
    <div className="max-w-4xl mx-auto">
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
            <div className="space-y-4">
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
                    {certificateInfo.isValid ? (
                      <>
                        <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                        <span className="text-green-700 text-sm font-medium">Valid Format</span>
                      </>
                    ) : (
                      <>
                        <div className="w-2 h-2 bg-red-500 rounded-full mr-2"></div>
                        <span className="text-red-700 text-sm font-medium">Invalid Format</span>
                      </>
                    )}
                  </div>
                </div>
              </div>

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

              <div className="bg-amber-50 border border-amber-200 p-4 rounded-lg">
                <div className="flex items-start">
                  <svg className="w-5 h-5 text-amber-500 mr-2 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <div>
                    <h3 className="text-sm font-medium text-amber-800 mb-1">Note</h3>
                    <p className="text-sm text-amber-700">This is a basic certificate format validator. For detailed certificate analysis including subject, issuer, validity dates, and extensions, a full ASN.1/X.509 parser would be required.</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
