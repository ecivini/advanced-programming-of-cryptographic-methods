'use client';
import React, { useState } from 'react';
import { CA_URL } from '../utils/constants';

export default function CommitPage() {
  const [email, setEmail] = useState('');
  const [pubkey, setPubkey] = useState('');
  const [status, setStatus] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setStatus('Submitting...');
    
    try {
      const IdUrl = CA_URL + '/v1/identity';
      const res = await fetch(IdUrl, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          public_key: pubkey,
        }),
      });
      
      if (!res.ok) throw new Error(await res.text());
      setStatus('✅ Identity committed successfully!');
    } catch (err) {
      setStatus(`❌ Error: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handlePubkeyFile = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      setPubkey(event.target.result);
    };
    reader.readAsText(file);
  };

  return (
    <div className="max-w-2xl mx-auto">
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-12 h-12 bg-gradient-to-r from-green-500 to-green-600 rounded-2xl mb-4">
          <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
        <h1 className="text-3xl font-bold text-slate-800 mb-2">Commit Identity</h1>
        <p className="text-slate-600">Submit your public key to receive a challenge for certificate generation</p>
      </div>

      <div className="card p-8">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="label">Email Address</label>
            <input
              type="email"
              required
              className="input"
              placeholder="your.email@example.com"
              value={email}
              onChange={e => setEmail(e.target.value)}
            />
            <p className="text-sm text-slate-500 mt-2">Challenge will be sent to this email address</p>
          </div>

          <div>
            <label className="label">Public Key (PEM format)</label>
            <div className="space-y-3">
              <div className="flex gap-2">
                <input
                  type="file"
                  accept=".pem,.pub,.key,.txt"
                  onChange={handlePubkeyFile}
                  className="hidden"
                  id="pubkeyFileInput"
                />
                <label
                  htmlFor="pubkeyFileInput"
                  className="btn btn-secondary cursor-pointer"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  Upload Public Key
                </label>
                <span className="text-sm text-slate-500 self-center">or paste below</span>
              </div>
              <textarea
                required
                rows={8}
                className="input font-mono resize-none"
                placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"
                value={pubkey}
                onChange={e => setPubkey(e.target.value)}
              />
            </div>
            <p className="text-sm text-slate-500 mt-2">Paste your PEM-encoded public key here, including the BEGIN/END lines.</p>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className={`btn btn-primary w-full ${isLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {isLoading ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                Submitting...
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                </svg>
                Commit Identity
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
      </div>
    </div>
  );
}
