'use client';
import React, { useState } from 'react';

export default function CommitPage() {
  const [email, setEmail] = useState('');
  const [pubkey, setPubkey] = useState('');
  const [keyType, setKeyType] = useState('ECDSA'); 
  const [status, setStatus] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setStatus('Submitting...');
    try {
      if (keyType !== 'ECDSA' && keyType !== 'RSA_2048' && keyType !== 'RSA_4096') {
        // console.error('Invalid key type selected:', keyType);
        setStatus('Error: Invalid key type selected.');
        return;
      }

      const IdUrl = process.env.NEXT_PUBLIC_CA_URL + '/v1/identity';
      const res = await fetch(IdUrl, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          public_key: pubkey,
          key_type: keyType,
        }),
      });
      if (!res.ok) throw new Error(await res.text());
      setStatus('✅ Identity committed successfully!');
    } catch (err) {
      // console.error('Key type ' + keyType + ' Error:', err);
      setStatus(`❌ Error: ${err.message}`);
    }
  };

  return (
    <div className="max-w-xl mx-auto p-6">
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
        <div>
          <label className="block font-medium">Key Type</label>
          <select
            required
            className="w-full mt-1 p-2 border rounded"
            value={keyType}
            onChange={e => setKeyType(e.target.value)}
          >
            <option value="ECDSA">ECDSA</option>
            <option value="RSA_2048">RSA 2048</option>
            <option value="RSA_4096">RSA 4096</option>
          </select>
        </div>
        <button
          type="submit"
          className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
        >
          Commit Identity
        </button>
      </form>
      {status && <p className="mt-4 text-center">{status}</p>}
    </div>
  );
}
