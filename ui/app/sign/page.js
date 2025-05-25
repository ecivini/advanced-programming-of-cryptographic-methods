'use client';
import React, { useState } from 'react';
import { stringToArrayBuffer, importPrivateKey, signData } from '../../utils/crypto';

export default function SignPage() {
  const [challenge, setChallenge] = useState('');
  const [privKey, setPrivKey] = useState('');
  const [signature, setSignature] = useState(null);
  const [error, setError] = useState(null);

  const handleSign = async e => {
    e.preventDefault();
    setError(null);
    setSignature(null);
    try {
      const key = await importPrivateKey(privKey);
      const sigBuf = await signData(key, stringToArrayBuffer(challenge));
      const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
      setSignature(sigB64);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div>
      <h2 className="text-2xl font-semibold mb-4">Sign Challenge</h2>
      <form onSubmit={handleSign} className="bg-white p-6 rounded shadow space-y-4">
        <div>
          <label className="block font-medium">Challenge</label>
          <textarea
            required
            className="w-full mt-1 h-32 p-2 border rounded font-mono"
            value={challenge}
            onChange={e => setChallenge(e.target.value)}
          />
        </div>
        <div>
          <label className="block font-medium">Private Key (PEM)</label>
          <textarea
            required
            className="w-full mt-1 h-40 p-2 border rounded font-mono"
            value={privKey}
            onChange={e => setPrivKey(e.target.value)}
          />
        </div>
        <button
          type="submit"
          className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700"
        >
          Generate Signature
        </button>
      </form>
      {error && <p className="mt-4 text-red-500">Error: {error}</p>}
      {signature && (
        <div className="mt-4">
          <h3 className="font-medium">Signature (Base64)</h3>
          <textarea
            readOnly
            className="w-full mt-1 h-32 p-2 border rounded font-mono"
            value={signature}
          />
        </div>
      )}
    </div>
  );
}