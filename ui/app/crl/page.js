'use client';
import React, { useEffect, useState } from 'react';
import { CA_URL } from '../utils/constants';

export default function CrlPage() {
  const [crl, setCrl] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(100);
  const [hasMore, setHasMore] = useState(true);

  useEffect(() => {
    const fetchCRL = async () => {
      try {
        setLoading(true);
        setError(null);
        
        // Generate required nonce and timestamp for signed responses
        const nonce = Math.floor(Math.random() * 999999) + 1; // Ensure nonce is between 1 and 1000000
        const timestamp = new Date().toISOString();
        const crlURL = `${CA_URL}/v1/crl?page=${page}&page_size=${pageSize}&nonce=${nonce}&timestamp=${encodeURIComponent(timestamp)}`;
        const res = await fetch(crlURL);
        
        if (!res.ok) {
          if (res.status === 404) {
            // No more data
            setHasMore(false);
            if (page === 1) {
              setCrl([]);
            }
            setLoading(false);
            return;
          }
          throw new Error(`HTTP error! status: ${res.status}`);
        }
        
        const data = await res.json();
        
        // Backend returns a signed response with structure: {response_data: {revoked_certificates: [...]}}
        let certificates = [];
        if (data.response_data && data.response_data.revoked_certificates) {
          certificates = data.response_data.revoked_certificates;
        } else if (Array.isArray(data)) {
          // Fallback for direct array response
          certificates = data;
        }
        
        if (page === 1) {
          setCrl(certificates);
        } else {
          setCrl(prev => [...prev, ...certificates]);
        }
        
        setHasMore(certificates.length === pageSize);
        setLoading(false);
      } catch (err) {
        setError(err.message);
        setLoading(false);
      }
    };

    fetchCRL();
  }, [page, pageSize]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-yellow-600 mx-auto mb-4"></div>
          <p className="text-slate-600">Loading certificate revocation list...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-2xl mx-auto">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
          <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h3 className="text-lg font-semibold text-red-800 mb-2">Error Loading CRL</h3>
          <p className="text-red-700">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4">
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-12 h-12 bg-gradient-to-r from-yellow-500 to-yellow-600 rounded-2xl mb-4">
          <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
          </svg>
        </div>
        <h1 className="text-3xl font-bold text-slate-800 mb-2">Certificate Revocation List</h1>
        <p className="text-slate-600">View certificates that have been revoked by the Certificate Authority</p>
      </div>

      <div className="card p-10">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-semibold text-slate-800 mb-2">Revoked Certificates</h2>
            <p className="text-slate-600">
              {crl.length === 0 ? 'No certificates have been revoked' : `${crl.length} certificate(s) revoked`}
            </p>
          </div>
          <div className="w-10 h-10 bg-yellow-50 rounded-lg flex items-center justify-center">
            <svg className="w-5 h-5 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
          </div>
        </div>

        {crl.length === 0 ? (
          <div className="text-center py-12">
            <div className="w-16 h-16 bg-green-50 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h3 className="text-lg font-semibold text-slate-800 mb-2">No Revoked Certificates</h3>
            <p className="text-slate-600">All issued certificates are currently valid and active.</p>
          </div>
        ) : (
          <div className="w-full">
            <table className="w-full table-auto">
              <thead>
                <tr className="border-b border-slate-200">
                  <th className="text-left py-4 px-6 font-semibold text-slate-700 w-1/2">Serial Number</th>
                  <th className="text-left py-4 px-6 font-semibold text-slate-700 w-1/3">Revocation Date</th>
                  <th className="text-left py-4 px-6 font-semibold text-slate-700 w-1/6">Status</th>
                </tr>
              </thead>
              <tbody>
                {crl.map((entry, index) => (
                  <tr key={entry.serial_number || index} className="border-b border-slate-100 last:border-0 hover:bg-slate-50">
                    <td className="py-4 px-6 font-mono text-sm text-slate-800 break-all">{entry.serial_number}</td>
                    <td className="py-4 px-6 text-slate-600 whitespace-nowrap">
                      {entry.revocation_date ? new Date(entry.revocation_date).toLocaleString() : 'N/A'}
                    </td>
                    <td className="py-4 px-6">
                      <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800">
                        <svg className="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                        </svg>
                        Revoked
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        
        {/* Pagination */}
        {crl.length > 0 && (
          <div className="mt-8 flex items-center justify-between border-t border-slate-200 pt-8">
            <div className="text-sm text-slate-600">
              Showing {crl.length} certificate(s)
            </div>
            <div className="flex gap-3">
              {page > 1 && (
                <button
                  onClick={() => setPage(1)}
                  className="btn btn-secondary"
                >
                  <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6" />
                  </svg>
                  Reset to First Page
                </button>
              )}
              {hasMore && (
                <button
                  onClick={() => setPage(prev => prev + 1)}
                  disabled={loading}
                  className="btn btn-primary"
                >
                  {loading ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Loading...
                    </>
                  ) : (
                    <>
                      <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                      </svg>
                      Load More Certificates
                    </>
                  )}
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="mt-8 text-center">
        <p className="text-sm text-slate-500">
          This list contains certificates that have been revoked and should not be trusted.
        </p>
      </div>
    </div>
  );
}