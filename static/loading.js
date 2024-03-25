// Reference to loading text element
const loadingText = document.getElementById('loadingText');

// Show loading text
loadingText.style.display = 'block';

// Fetch JSON data
fetch('/your_endpoint')
  .then(response => {
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    return response.json();
  })
  .then(data => {
    // Process JSON data and display it (replace this with your own logic)
    const dataContainer = document.getElementById('dataContainer');
    dataContainer.textContent = JSON.stringify(data);

    // Hide loading text
    loadingText.style.display = 'none';
  })
  .catch(error => {
    console.error('There was a problem with the fetch operation:', error);
    
    // Hide loading text in case of error
    loadingText.style.display = 'none';
  });
