// Certificate parsing utilities for ASN.1/DER certificate parsing

import { generateNonce } from "./crypto";

// Polyfill for atob if not available
function base64Decode(str) {
  if (typeof atob === 'function') {
    return atob(str);
  }
  
  // Simple base64 decode fallback (for Node.js or older browsers)
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(str, 'base64').toString('binary');
  }
  
  throw new Error('No base64 decode function available');
}

async function getCaPublicKey() {
  const caUrl = process.env.NEXT_PUBLIC_CA_URL + '/v1/info/pk';
  const resp = await fetch(caUrl, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
  })

  if (!resp.ok) {
    throw new Error(`Failed to fetch CA public key: ${resp.status} ${resp.statusText}`);
  }   

  const data = await resp.json();
  const publicKeyPem = data.public_key;
  const publicKeyBase64 = publicKeyPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const publicKeyBytes = Uint8Array.fromBase64(publicKeyBase64);

  console.log('CA Public Key hex:', (new Uint8Array(publicKeyBytes)).toHex());

  return crypto.subtle.importKey(
    'spki', publicKeyBytes,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, ['verify']
  );
}

// ref: https://jose.readthedocs.io/en/latest/
function derToJose(der) {
  let offset = 0;

  if (der[offset++] !== 0x30) throw new Error("Invalid DER format: expected SEQUENCE");
  const seqLen = der[offset++];
  if (seqLen > der.length - offset) throw new Error("Invalid DER length");

  if (der[offset++] !== 0x02) throw new Error("Invalid DER format: expected INTEGER for r");
  let rLen = der[offset++];
  let r = der.slice(offset, offset + rLen);
  offset += rLen;

  if (der[offset++] !== 0x02) throw new Error("Invalid DER format: expected INTEGER for s");
  let sLen = der[offset++];
  let s = der.slice(offset, offset + sLen);

  // Remove leading zeroes for r and s if present (due to ASN.1 encoding)
  while (r.length > 32 && r[0] === 0x00) r = r.slice(1);
  while (s.length > 32 && s[0] === 0x00) s = s.slice(1);

  if (r.length > 32 || s.length > 32)
    throw new Error("r or s length is too long for P-256");

  const rPadded = new Uint8Array(32);
  const sPadded = new Uint8Array(32);
  rPadded.set(r, 32 - r.length);
  sPadded.set(s, 32 - s.length);

  return new Uint8Array([...rPadded, ...sPadded]);
}


async function signedResponseIsValid(response) {
  const caPublicKey = await getCaPublicKey();

  const responseData = response.response_data;
  const responseDataStr = JSON.stringify(responseData);
  const responseDataEncoded = (new TextEncoder()).encode(responseDataStr);
  const signatureBytes = Uint8Array.fromBase64(response.signature);
  const signatureDer = derToJose(signatureBytes);

  return await window.crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    caPublicKey,
    signatureDer,
    responseDataEncoded,
  );
}

// Robust base64 cleaning and validation
function cleanAndValidateBase64(base64String) {
  // Remove all whitespace and non-base64 characters
  let cleaned = base64String.replace(/[^A-Za-z0-9+/=]/g, '');
  
  // Remove any existing padding
  cleaned = cleaned.replace(/=+$/, '');
  
  // Validate base64 characters
  if (!/^[A-Za-z0-9+/]*$/.test(cleaned)) {
    throw new Error('Invalid base64 characters found');
  }
  
  // Add proper padding
  const paddingNeeded = (4 - (cleaned.length % 4)) % 4;
  cleaned += '='.repeat(paddingNeeded);
  
  console.log('Cleaned base64 length:', cleaned.length, 'padding added:', paddingNeeded);
  
  return cleaned;
}

// Parse ASN.1/DER certificate to extract serial number and validity dates
export function parseCertificateInfo(certificateData) {
  try {
    // Input validation
    if (!certificateData || typeof certificateData !== 'string') {
      throw new Error('Invalid certificate data');
    }

    let certificatePEM;
    
    // Check if the input is JSON containing a certificate
    if (certificateData.trim().startsWith('{')) {
      try {
        const jsonData = JSON.parse(certificateData);
        if (jsonData.certificate) {
          certificatePEM = jsonData.certificate;
          console.log('Extracted certificate from JSON object');
        } else {
          throw new Error('No certificate field found in JSON object');
        }
      } catch (jsonError) {
        console.warn('Failed to parse as JSON:', jsonError);
        throw new Error('Invalid JSON certificate data: ' + jsonError.message);
      }
    } else {
      // Assume it's raw PEM data
      certificatePEM = certificateData;
    }

    // Check if it looks like a PEM certificate
    if (!certificatePEM.includes('-----BEGIN CERTIFICATE-----') || 
        !certificatePEM.includes('-----END CERTIFICATE-----')) {
      throw new Error('Invalid PEM certificate format');
    }

    console.log('Processing PEM certificate, length:', certificatePEM.length);

    const lines = certificatePEM.split('\n');
    const base64Data = lines
      .filter(line => !line.startsWith('-----') && line.trim() !== '')
      .join('')
      .replace(/\s/g, '');
    
    if (!base64Data) {
      throw new Error('No certificate data found in PEM');
    }

    console.log('Raw base64 data length:', base64Data.length);
    console.log('First 100 chars:', base64Data.substring(0, 100));
    
    let binaryData;
    try {
      // Cross-browser compatible base64 decoding
      if (typeof atob !== 'function') {
        throw new Error('atob function not available in this environment');
      }
      
      // Clean and validate base64 data
      const cleanBase64 = cleanAndValidateBase64(base64Data);
      
      console.log('Cleaned base64 length:', cleanBase64.length);
      console.log('Attempting to decode...');
      
      // Try to decode with better error handling
      let decodedString;
      try {
        decodedString = base64Decode(cleanBase64);
      } catch (decodeError) {
        console.error('Direct decode failed:', decodeError);
        
        // Try alternative approach - decode in chunks
        const chunkSize = 4000;
        let chunks = [];
        for (let i = 0; i < cleanBase64.length; i += chunkSize) {
          const chunk = cleanBase64.slice(i, i + chunkSize);
          try {
            chunks.push(base64Decode(chunk));
          } catch (chunkError) {
            console.error(`Chunk ${i}-${i+chunkSize} failed:`, chunkError);
            throw new Error(`Failed to decode base64 chunk at position ${i}: ${chunkError.message}`);
          }
        }
        decodedString = chunks.join('');
      }
      
      binaryData = Uint8Array.from(decodedString, c => c.charCodeAt(0));
      
      if (binaryData.length === 0) {
        throw new Error('Decoded certificate data is empty');
      }
      
      console.log('Binary data length:', binaryData.length);
      console.log('First few bytes:', Array.from(binaryData.slice(0, 10)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(' '));
      
    } catch (e) {
      console.warn('Failed to decode base64 certificate data:', e);
      console.warn('Base64 data sample:', base64Data.substring(0, 200));
      throw new Error('Invalid base64 certificate data: ' + e.message);
    }

    // Helper function to parse ASN.1 length
    const parseLength = (data, offset) => {
      if (data[offset] & 0x80) {
        const lengthBytes = data[offset] & 0x7f;
        let length = 0;
        for (let i = 1; i <= lengthBytes; i++) {
          length = (length << 8) | data[offset + i];
        }
        return { length, nextOffset: offset + lengthBytes + 1 };
      } else {
        return { length: data[offset], nextOffset: offset + 1 };
      }
    };

    // Helper function to parse ASN.1 time (UTCTime or GeneralizedTime)
    const parseTime = (data, offset) => {
      if (offset >= data.length) {
        throw new Error('Unexpected end of data while parsing time');
      }
      
      const tag = data[offset];
      const lengthInfo = parseLength(data, offset + 1);
      
      if (lengthInfo.nextOffset + lengthInfo.length > data.length) {
        throw new Error('Time data extends beyond certificate bounds');
      }
      
      const timeBytes = data.slice(lengthInfo.nextOffset, lengthInfo.nextOffset + lengthInfo.length);
      const timeString = String.fromCharCode(...timeBytes);
      
      let date;
      if (tag === 0x17) { // UTCTime (YYMMDDHHMMSSZ)
        if (timeString.length < 13) {
          throw new Error('Invalid UTCTime format');
        }
        const year = parseInt(timeString.substr(0, 2));
        const fullYear = year >= 50 ? 1900 + year : 2000 + year;
        const month = parseInt(timeString.substr(2, 2)) - 1;
        const day = parseInt(timeString.substr(4, 2));
        const hour = parseInt(timeString.substr(6, 2));
        const minute = parseInt(timeString.substr(8, 2));
        const second = parseInt(timeString.substr(10, 2));
        date = new Date(fullYear, month, day, hour, minute, second);
      } else if (tag === 0x18) { // GeneralizedTime (YYYYMMDDHHMMSSZ)
        if (timeString.length < 15) {
          throw new Error('Invalid GeneralizedTime format');
        }
        const year = parseInt(timeString.substr(0, 4));
        const month = parseInt(timeString.substr(4, 2)) - 1;
        const day = parseInt(timeString.substr(6, 2));
        const hour = parseInt(timeString.substr(8, 2));
        const minute = parseInt(timeString.substr(10, 2));
        const second = parseInt(timeString.substr(12, 2));
        date = new Date(year, month, day, hour, minute, second);
      } else {
        throw new Error(`Unknown time format tag: 0x${tag.toString(16)}`);
      }
      
      if (isNaN(date.getTime())) {
        throw new Error('Invalid date parsed from certificate');
      }
      
      return {
        date,
        nextOffset: lengthInfo.nextOffset + lengthInfo.length
      };
    };

    let offset = 0;
    
    // Skip outer SEQUENCE
    if (offset >= binaryData.length || binaryData[offset] !== 0x30) {
      throw new Error('Invalid certificate format: expected SEQUENCE');
    }
    offset++;
    
    // Skip outer sequence length
    const outerLengthInfo = parseLength(binaryData, offset);
    offset = outerLengthInfo.nextOffset;
    
    // Skip tbsCertificate SEQUENCE
    if (binaryData[offset] !== 0x30) throw new Error('Invalid tbsCertificate format');
    offset++;
    
    // Skip tbsCertificate length
    const tbsLengthInfo = parseLength(binaryData, offset);
    offset = tbsLengthInfo.nextOffset;
    
    // Skip version (optional, context-specific [0])
    if (binaryData[offset] === 0xa0) {
      offset++;
      const versionLengthInfo = parseLength(binaryData, offset);
      offset = versionLengthInfo.nextOffset + versionLengthInfo.length;
    }
    
    // Parse serial number
    if (binaryData[offset] !== 0x02) throw new Error('Serial number not found');
    offset++;
    
    const serialLengthInfo = parseLength(binaryData, offset);
    offset = serialLengthInfo.nextOffset;
    
    const serialBytes = binaryData.slice(offset, offset + serialLengthInfo.length);
    
    // Convert serial number to decimal string
    let serialNumber = '';
    for (let i = 0; i < serialBytes.length; i++) {
      if (i === 0 && serialBytes[i] === 0) continue; // Skip leading zero
      serialNumber = (BigInt(serialNumber || '0') * BigInt(256) + BigInt(serialBytes[i])).toString();
    }
    
    offset += serialLengthInfo.length;
    
    // Skip signature algorithm
    if (binaryData[offset] !== 0x30) throw new Error('Signature algorithm not found');
    offset++;
    const sigAlgLengthInfo = parseLength(binaryData, offset);
    offset = sigAlgLengthInfo.nextOffset + sigAlgLengthInfo.length;
    
    // Skip issuer
    if (binaryData[offset] !== 0x30) throw new Error('Issuer not found');
    offset++;
    const issuerLengthInfo = parseLength(binaryData, offset);
    offset = issuerLengthInfo.nextOffset + issuerLengthInfo.length;
    
    // Parse validity (SEQUENCE of two times)
    if (binaryData[offset] !== 0x30) throw new Error('Validity not found');
    offset++;
    const validityLengthInfo = parseLength(binaryData, offset);
    offset = validityLengthInfo.nextOffset;
    
    // Parse notBefore
    const notBeforeInfo = parseTime(binaryData, offset);
    offset = notBeforeInfo.nextOffset;
    
    // Parse notAfter
    const notAfterInfo = parseTime(binaryData, offset);
    
    console.log('Successfully parsed certificate:', {
      serialNumber: serialNumber || '0',
      notBefore: notBeforeInfo.date.toISOString(),
      notAfter: notAfterInfo.date.toISOString()
    });

    return {
      serialNumber: serialNumber || '0',
      notBefore: notBeforeInfo.date,
      notAfter: notAfterInfo.date
    };
  } catch (error) {
    console.error('Failed to parse certificate info:', error);
    console.error('Certificate data preview:', certificateData?.substring(0, 200) + '...');
    return {
      serialNumber: null,
      notBefore: null,
      notAfter: null,
      error: error.message
    };
  }
}

// Check if certificate is revoked by querying certificate status
export async function checkRevocationStatus(serialNumber, caUrl) {
  try {    
    // Generate cryptographically secure nonce and timestamp
    const nonce = generateNonce();
    const timestamp = new Date().toISOString();
    
    // Query certificate status API with POST request and required parameters
    const certURL = `${caUrl}/v1/certificate/status`;
    const res = await fetch(certURL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        serial_number: serialNumber,
        nonce: nonce,
        timestamp: timestamp
      })
    });
    
    if (!res.ok) {
      // If certificate not found or other error, assume it's active (not revoked)
      console.warn('Cannot check certificate status:', res.status);
      return { isRevoked: false, revocationDate: null, error: null, verified: false };
    }
    
    const statusData = await res.json();
    
    // Verify the CA response signature and authenticity
    const responseValid = await signedResponseIsValid(statusData);
    if (!responseValid) {
      console.error('CA response verification failed');
      return { 
        isRevoked: false, 
        revocationDate: null, 
        error: `CA response verification failed: invalid signature`,
        verified: false
      };
    }
    
    // Validate nonce matches our request
    const responseData = statusData.response_data;
    if (nonce !== responseData.nonce){
      console.error('Nonce validation failed:', nonceError.message);
      return { 
        isRevoked: false, 
        revocationDate: null, 
        error: `Nonce validation failed: ${nonceError.message}`,
        verified: false
      };
    }
    
    // Check if the certificate has revocation flag set
    console.log('Verified certificate status response:', responseData);
    return { 
      isRevoked: responseData.cert_status === 'revoked',
      revocationDate: responseData.revocation_time || null,
      error: null,
      verified: true,
      verificationDetails: "Successfully verified CA response signature and nonce"
    };
  } catch (error) {
    // If there's an error, assume certificate is active (not revoked)
    console.warn('Error checking certificate status:', error);
    return { 
      isRevoked: false, 
      revocationDate: null, 
      error: error.message,
      verified: false
    };
  }
}
