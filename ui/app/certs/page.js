'use client';

import React, { useState } from 'react';
import { CA_URL } from '../utils/constants';
import { parseCertificateInfo, checkRevocationStatus } from '../utils/certificate';
import { handleFileUpload, copyToClipboard, formatSerialNumber } from '../utils/ui';

export default function CertsPage() {
  const [certificatePEM, setCertificatePEM] = useState('');
  const [certificateInfo, setCertificateInfo] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [verificationStatus, setVerificationStatus] = useState(null);

  const certificateUploader = handleFileUpload(setCertificatePEM);

  // Parse certificate information
  const parseCertificate = async () => {
    if (!certificatePEM.trim()) {
      setError('Please provide a certificate');
      return;
    }

    setIsLoading(true);
    setError(null);
    setCertificateInfo(null);
    setVerificationStatus(null);

    try {
      const lines = certificatePEM.split('\n');
      const base64Data = lines
        .filter(line => !line.startsWith('-----'))
        .join('')
        .replace(/\s/g, '');

      // Parse certificate details including serial number and validity dates
      const certInfo = parseCertificateInfo(certificatePEM);
      
      // Check if certificate format is valid
      const hasValidFormat = certificatePEM.includes('-----BEGIN CERTIFICATE-----') && 
                           certificatePEM.includes('-----END CERTIFICATE-----');

      let revocationStatus = { isRevoked: false, revocationDate: null, error: null, verified: false };
      
      // Only check revocation status if we have a serial number and valid format
      if (certInfo.serialNumber && hasValidFormat) {
        revocationStatus = await checkRevocationStatus(certInfo.serialNumber, CA_URL);
        
        // Set verification status for display
        if (revocationStatus.verified && revocationStatus.verificationDetails) {
          const { verificationDetails } = revocationStatus;
          setVerificationStatus({
            status: 'VERIFIED',
            message: 'Certificate status verified from CA',
            details: [
              `Algorithm: ${verificationDetails.algorithm}`,
              `Responder: ${verificationDetails.responder}`,
              `Timestamp: ${verificationDetails.timestamp}`,
              `Nonce: ${verificationDetails.nonce}`
            ]
          });
        } else if (revocationStatus.error) {
          setVerificationStatus({
            status: 'FAILED',
            message: revocationStatus.error,
            details: []
          });
        }
      }

      // Check if certificate is currently valid (not expired) - but revoked certificates are never valid
      const now = new Date();
      const isExpired = certInfo.notAfter && now > certInfo.notAfter;
      const isNotYetValid = certInfo.notBefore && now < certInfo.notBefore;

      const info = {
        format: 'X.509',
        encoding: 'PEM',
        size: base64Data.length,
        lines: lines.length,
        hasBeginMarker: certificatePEM.includes('-----BEGIN CERTIFICATE-----'),
        hasEndMarker: certificatePEM.includes('-----END CERTIFICATE-----'),
        hasValidFormat: hasValidFormat,
        serialNumber: certInfo.serialNumber,
        notBefore: certInfo.notBefore,
        notAfter: certInfo.notAfter,
        isExpired: isExpired,
        isNotYetValid: isNotYetValid,
        isRevoked: revocationStatus.isRevoked,
        revocationDate: revocationStatus.revocationDate,
        // Certificate is valid if it has correct format AND is not revoked AND is within validity period
        isValid: hasValidFormat && !revocationStatus.isRevoked && !isExpired && !isNotYetValid
      };

      setCertificateInfo(info);
      
      // Do not auto-populate revocation message - let user enter it manually
    } catch (err) {
      setError(`Failed to parse certificate: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Copy to clipboard with feedback
  const handleCopy = async (text, successMessage = 'Copied to clipboard') => {
    await copyToClipboard(
      text,
      () => {
        setError(null);
        // Show success feedback briefly
        const originalError = error;
        setError(`✅ ${successMessage}`);
        setTimeout(() => setError(originalError), 2000);
      },
      (errorMessage) => setError(`Failed to copy: ${errorMessage}`)
    );
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
                onChange={certificateUploader}
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
                  onClick={() => handleCopy(certificatePEM, 'Certificate copied!')}
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
          <div className="flex items-center mb-4">
            <h2 className="text-xl font-semibold text-slate-800">Certificate Information</h2>
            {verificationStatus && verificationStatus.status === 'VERIFIED' && (
              <div className="flex items-center ml-3">
                <svg className="w-5 h-5 text-green-600 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span className="text-green-700 text-sm font-medium">CA Verified</span>
              </div>
            )}
          </div>
          
          {/* CA Verification Status - Only show error banners */}
          {verificationStatus && verificationStatus.status === 'FAILED' && (
            <div className="mb-6 p-4 rounded-lg border bg-red-50 border-red-200">
              <div className="flex items-center mb-2">
                <svg className="w-5 h-5 text-red-600 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span className="font-medium text-sm text-red-800">
                  CA Response FAILED
                </span>
              </div>
              <p className="text-sm text-red-700">
                {verificationStatus.message}
              </p>
            </div>
          )}
          
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
                    ) : certificateInfo.isExpired ? (
                      <>
                        <div className="w-2 h-2 bg-orange-500 rounded-full mr-2"></div>
                        <span className="text-orange-700 text-sm font-medium">Expired</span>
                      </>
                    ) : certificateInfo.isNotYetValid ? (
                      <>
                        <div className="w-2 h-2 bg-yellow-500 rounded-full mr-2"></div>
                        <span className="text-yellow-700 text-sm font-medium">Not Yet Valid</span>
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
                  {certificateInfo.isExpired && certificateInfo.notAfter && (
                    <p className="text-xs text-slate-500 mt-1">
                      Expired: {certificateInfo.notAfter.toLocaleString()}
                    </p>
                  )}
                  {certificateInfo.isNotYetValid && certificateInfo.notBefore && (
                    <p className="text-xs text-slate-500 mt-1">
                      Valid from: {certificateInfo.notBefore.toLocaleString()}
                    </p>
                  )}
                </div>
              </div>

              {/* Serial Number Display */}
              {certificateInfo.serialNumber && (
                <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-sm font-medium text-slate-600">Serial Number</label>
                    <button
                      onClick={() => handleCopy(certificateInfo.serialNumber, 'Serial number copied!')}
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

              {/* Validity Period Display - Show for all certificates with appropriate dates */}
              {(certificateInfo.notBefore || certificateInfo.notAfter || certificateInfo.revocationDate) && (
                <div className="bg-slate-50 p-4 rounded-lg">
                  <label className="text-sm font-medium text-slate-600 block mb-3">
                    {certificateInfo.isRevoked ? 'Validity Period (Before Revocation)' : 'Validity Period'}
                  </label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {certificateInfo.notBefore && (
                      <div>
                        <label className="text-xs font-medium text-slate-500 block mb-1">Valid From </label>
                        <div className="flex items-center">
                          <svg className="w-4 h-4 text-slate-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                          </svg>
                          <p className="text-slate-800 text-sm">
                            {certificateInfo.notBefore.toLocaleString()}
                          </p>
                        </div>
                      </div>
                    )}
                    {/* For revoked certificates, show revocation date as end date. For others, show notAfter */}
                    {(certificateInfo.isRevoked ? certificateInfo.revocationDate : certificateInfo.notAfter) && (
                      <div>
                        <label className="text-xs font-medium text-slate-500 block mb-1">
                          {certificateInfo.isRevoked ? 'Valid Until (Revoked)' : 'Valid Until'}
                        </label>
                        <div className="flex items-center">
                          <svg className="w-4 h-4 text-slate-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                          </svg>
                          <p className={`text-sm ${
                            certificateInfo.isRevoked ? 'text-red-700 font-medium' : 
                            certificateInfo.isExpired ? 'text-red-700 font-medium' : 
                            'text-slate-800'
                          }`}>
                            {certificateInfo.isRevoked 
                              ? new Date(certificateInfo.revocationDate).toLocaleString()
                              : certificateInfo.notAfter.toLocaleString()
                            }
                          </p>
                        </div>
                      </div>
                    )}
                  </div>
                  {/* Validity status indicator */}
                  {(certificateInfo.notBefore && (certificateInfo.notAfter || certificateInfo.revocationDate)) && (
                    <div className="mt-3 pt-3 border-t border-slate-200">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-500">Validity Status:</span>
                        <span className={`font-medium ${
                          certificateInfo.isRevoked ? 'text-red-700' :
                          certificateInfo.isExpired ? 'text-red-700' : 
                          certificateInfo.isNotYetValid ? 'text-yellow-700' : 
                          'text-green-700'
                        }`}>
                          {certificateInfo.isRevoked ? 'Revoked' :
                          certificateInfo.isExpired ? 'Expired' : 
                          certificateInfo.isNotYetValid ? 'Not Yet Valid' : 
                          'Currently Valid'}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Certificate Actions */}
              {certificateInfo.hasValidFormat && certificateInfo.serialNumber && !certificateInfo.isRevoked && !certificateInfo.isExpired && !certificateInfo.isNotYetValid && (
                <div className="flex justify-center gap-4">
                  <button
                    onClick={() => window.location.href = `/revoke?serial=${certificateInfo.serialNumber}`}
                    className="btn btn-danger"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                    Revoke Certificate
                  </button>
                  <button
                    onClick={() => window.location.href = `/renew?serial=${certificateInfo.serialNumber}`}
                    className="btn btn-primary"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                    Renew Certificate
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
