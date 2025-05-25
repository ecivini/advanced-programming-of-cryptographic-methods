'use client';
import React, { useState } from 'react';

export default function CommitPage() {
  const [email, setEmail] = useState('');
  const [pubkey, setPubkey] = useState('');
  const [status, setStatus] = useState(null);

  const handleSubmit = async e => {
    e.preventDefault();
    setStatus('Submitting...');
    try {
      const res = await fetch('/api/commit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, publicKey: pubkey }),
      });
      if (!res.ok) throw new Error(await res.text());
      setStatus('Identity committed successfully!');
    } catch (err) {
      setStatus(`Error: ${err.message}`);
    }
  };

  return (
    <div>
      <h2 className="text-2xl font-semibold mb-4">Submit Identity</h2>
      <form onSubmit={handleSubmit} className="bg-white p-6 rounded shadow space-y-4">
        <div>
          <label className="block font-medium">Email</label>
          <input
            type="email"
            required
            className="w-full mt-1 p-2 border rounded"
            value={email}
            onChange={e => setEmail(e.target.value)}
          />
        </div>
        <div>
          <label className="block font-medium">Public Key (PEM)</label>
          <textarea
            required
            className="w-full mt-1 h-40 p-2 border rounded font-mono"
            value={pubkey}
            onChange={e => setPubkey(e.target.value)}
          />
        </div>
        <button
          type="submit"
          className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
        >
          Commit Identity
        </button>
      </form>
      {status && <p className="mt-4">{status}</p>}
    </div>
  );
}