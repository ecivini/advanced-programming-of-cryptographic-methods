// Shared API utility functions for HTTP requests and error handling

// Parse error response from fetch API
export const parseErrorResponse = async (response) => {
  const contentType = response.headers.get('content-type') || '';
  
  if (contentType.includes('application/json')) {
    const errorData = await response.json();
    return errorData.error || JSON.stringify(errorData);
  } else {
    return await response.text();
  }
};

// Make an API request with JSON data and handle errors
export const makeApiRequest = async (url, data, method = 'POST', expectJson = true) => {
  const response = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });

  if (!response.ok) {
    const errorMessage = await parseErrorResponse(response);
    throw new Error(errorMessage || `Request failed: HTTP ${response.status}`);
  }

  // Return parsed response based on expected format
  if (expectJson) {
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      return await response.json();
    } else {
      return { message: await response.text() };
    }
  } else {
    return await response.text();
  }
};
