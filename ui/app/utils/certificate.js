// Certificate parsing utilities for ASN.1/DER certificate parsing

// Parse ASN.1/DER certificate to extract serial number and validity dates
export function parseCertificateInfo(certificatePEM) {
  try {
    const lines = certificatePEM.split('\n');
    const base64Data = lines
      .filter(line => !line.startsWith('-----'))
      .join('')
      .replace(/\s/g, '');
    
    const binaryData = Uint8Array.from(atob(base64Data), c => c.charCodeAt(0));
    
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
      const tag = data[offset];
      const lengthInfo = parseLength(data, offset + 1);
      const timeBytes = data.slice(lengthInfo.nextOffset, lengthInfo.nextOffset + lengthInfo.length);
      const timeString = String.fromCharCode(...timeBytes);
      
      let date;
      if (tag === 0x17) { // UTCTime (YYMMDDHHMMSSZ)
        const year = parseInt(timeString.substr(0, 2));
        const fullYear = year >= 50 ? 1900 + year : 2000 + year;
        const month = parseInt(timeString.substr(2, 2)) - 1;
        const day = parseInt(timeString.substr(4, 2));
        const hour = parseInt(timeString.substr(6, 2));
        const minute = parseInt(timeString.substr(8, 2));
        const second = parseInt(timeString.substr(10, 2));
        date = new Date(fullYear, month, day, hour, minute, second);
      } else if (tag === 0x18) { // GeneralizedTime (YYYYMMDDHHMMSSZ)
        const year = parseInt(timeString.substr(0, 4));
        const month = parseInt(timeString.substr(4, 2)) - 1;
        const day = parseInt(timeString.substr(6, 2));
        const hour = parseInt(timeString.substr(8, 2));
        const minute = parseInt(timeString.substr(10, 2));
        const second = parseInt(timeString.substr(12, 2));
        date = new Date(year, month, day, hour, minute, second);
      } else {
        throw new Error('Unknown time format');
      }
      
      return {
        date,
        nextOffset: lengthInfo.nextOffset + lengthInfo.length
      };
    };

    let offset = 0;
    
    // Skip outer SEQUENCE
    if (binaryData[offset] !== 0x30) throw new Error('Invalid certificate format');
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
    
    return {
      serialNumber: serialNumber || '0',
      notBefore: notBeforeInfo.date,
      notAfter: notAfterInfo.date
    };
  } catch (error) {
    console.warn('Failed to parse certificate info:', error);
    return {
      serialNumber: null,
      notBefore: null,
      notAfter: null
    };
  }
}

// Check if certificate is revoked by querying certificate status
export async function checkRevocationStatus(serialNumber, caUrl) {
  try {
    // Query certificate status API to check if certificate is revoked
    const certURL = `${caUrl}/v1/certificate/${serialNumber}/status`;
    const res = await fetch(certURL);
    
    if (!res.ok) {
      // If certificate not found or other error, assume it's active (not revoked)
      console.warn('Cannot check certificate status:', res.status);
      return { isRevoked: false, revocationDate: null, error: null };
    }
    
    const statusData = await res.json();
    
    // Check if the certificate has revocation flag set
    return { 
      isRevoked: statusData.revoked || false, 
      revocationDate: statusData.revocation_date || null,
      error: null 
    };
  } catch (error) {
    // If there's an error, assume certificate is active (not revoked)
    console.warn('Error checking certificate status:', error);
    return { isRevoked: false, revocationDate: null, error: null };
  }
}
