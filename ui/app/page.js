'use client';
import React, { useEffect, useState } from 'react';

export default function HomePage() {
  const [caInfo, setCaInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

useEffect(() => {
  const caUrl = process.env.NEXT_PUBLIC_CA_URL + '/v1/info/pk';
  // console.log(`Fetching CA info from: ${caUrl}`);
  fetch(caUrl, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    cache: 'no-cache',
    next: {
      revalidate: 60, // Revalidate every 60 seconds
    },
  })
    .then(res => {
      if (!res.ok) {
        throw new Error(`Network response was not ok: ${res.statusText}`);
      }
      return res;

    })
    .then(res => res.json())
    .then(data => {
      setCaInfo(data);
      setLoading(false);
    })
    .catch(err => {
      setError(err.message);
      setLoading(false);
    });
}
, []);

  if (loading) {
    return <div className="text-center text-gray-500">Loading...</div>;
  }

  if (error) {
    return <div className="text-center text-red-500">Error: {error}</div>;
  }

  return (
    <div className="max-w-2xl mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4 text-center">Certificate Authority Information</h1>
      <pre className="bg-green-100 p-4 rounded-lg whitespace-pre-wrap break-words text-sm mx-auto  max-w-md">
        {caInfo && caInfo["public_key"]?.replaceAll('\\n', '\n')}
      </pre>
      {/* Button to copy the public key */}
      <div className="text-center mt-4">
        <button
          onClick={() => {
            navigator.clipboard.writeText(caInfo["public_key"])
              .then(() => alert('Public key copied to clipboard!'))
              .catch(err => alert('Failed to copy: ' + err));
          }}
          className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
        >
          Copy Public Key
        </button>
      </div>
    </div>
  );
}



