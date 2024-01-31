const endpointUrl = 'http://127.0.0.1:3000/api/auth/ClickStatus';

function makeRequest() {
  fetch(endpointUrl)
    .then(response => response.json())
    .then(data => {
      if (data.status === 'success' && data.message === 'User not clicked') {
        console.log('Continuing to make requests...');
        setTimeout(makeRequest, 1000); // Make the next request after 1 second
      } else if (data.status === 'success' && (data.message === 'User signup clicked')|| data.message ==='user signin') {
        console.log('Done');
      } else {
        console.error('Unexpected response:', data);
      }
    })
    .catch(error => {
      console.error('Error during request:', error);
    });
}

// Start making requests
makeRequest();
