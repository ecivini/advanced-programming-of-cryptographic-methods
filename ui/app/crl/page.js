'use client';
import React, { useEffect, useState } from 'react';

export default function CrlPage() {
  const [crl, setCrl] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const crlURL = process.env.NEXT_PUBLIC_CA_URL + '/v1/certificate/revoke';
    fetch(crlURL)
      .then(res => res.json())
      .then(data => {
        setCrl(data);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  if (loading) return <p>Loading CRL...</p>;
  if (error) return <p className="text-red-500">Error: {error}</p>;

  return (
    <div>
      <h2 className="text-2xl font-semibold mb-4">Certificate Revocation List</h2>
      <table className="min-w-full bg-white rounded shadow">
        <thead>
          <tr className="border-b">
            <th className="px-4 py-2 text-left">Serial Number</th>
            <th className="px-4 py-2 text-left">Revoked At</th>
          </tr>
        </thead>
        <tbody>
          {crl.map(entry => (
            <tr key={entry.serial} className="border-b last:border-0">
              <td className="px-4 py-2 font-mono">{entry.serial}</td>
              <td className="px-4 py-2">{new Date(entry.revokedAt).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}