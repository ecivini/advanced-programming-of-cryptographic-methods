// Shared UI utility functions for file handling and common operations

// Generic file upload handler that reads file as text
export const handleFileUpload = (callback) => (event) => {
  const file = event.target.files[0];
  if (file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      callback(e.target.result);
    };
    reader.readAsText(file);
  }
};

// Copy text to clipboard with optional success message callback
export const copyToClipboard = async (text, onSuccess, onError) => {
  try {
    await navigator.clipboard.writeText(text);
    if (onSuccess) onSuccess();
  } catch (err) {
    if (onError) onError(err.message);
  }
};

// Format serial number for display (first 5 and last 5 digits with ellipsis)
export const formatSerialNumber = (serialNumber) => {
  if (!serialNumber || serialNumber.length <= 10) {
    return serialNumber;
  }
  return `${serialNumber.slice(0, 5)}...${serialNumber.slice(-5)}`;
};

// Download text content as a file
export const downloadTextFile = (content, filename, mimeType = 'text/plain') => {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};
