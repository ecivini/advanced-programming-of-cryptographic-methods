'use client';
import React, { useState } from 'react';
import {
  stringToArrayBuffer,
  importPrivateKey,
  signData
} from '../../utils/crypto';

export default function SignPage() {
  const [challenge, setChallenge] = useState('');
  const [privKey, setPrivKey] = useState('');
  const [signature, setSignature] = useState(null);
  const [status, setStatus] = useState(null);

  const handleSign = async e => {
    e.preventDefault();
    setStatus('Signing…');
    try {
      const key = await importPrivateKey(privKey);
      const sigBuf = await signData(key, stringToArrayBuffer(challenge));
      const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
      setSignature(sigB64);

      const signURL = `${process.env.NEXT_PUBLIC_API_BASE_URL}/v1/certificate/sign`;
      const res = await fetch(signURL, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          challenge,
          signature: sigB64,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || `Server ${res.status}`);
      }

      const { certificate } = await res.json();
      console.log('Certificate issued:', certificate);
      setStatus(`Certificate issued:\n\n${certificate}`);
    } catch (err) {
      setStatus(`Error: ${err.message}`);
    }
  };

  return (
    <div>
      <h2 className="text-2xl font-semibold mb-4">Sign & Request Certificate</h2>
      <form onSubmit={handleSign} className="bg-white p-6 rounded shadow space-y-4">
        <div>
          <label className="block font-medium">Challenge (base64)</label>
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
          Sign & Request
        </button>
      </form>

      {signature && (
        <div className="mt-4">
          <h3 className="font-medium">Generated Signature (Base64)</h3>
          <textarea
            readOnly
            className="w-full mt-1 h-24 p-2 border rounded font-mono"
            value={signature}
          />
        </div>
      )}

      {status && (
        <pre className="mt-4 p-4 bg-gray-100 rounded whitespace-pre-wrap">{status}</pre>
      )}
    </div>
  );
}
