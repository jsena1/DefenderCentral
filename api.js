const apiKey = <your API key>

function scanURL() {
  const urlInput = document.getElementById('urlInput').value;
  const apiUrl = 'https://www.virustotal.com/api/v3/urls';
  const options = {
    method: 'POST',
    headers: {
      'x-apikey': apiKey,
      'content-type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({ url: urlInput })
  };

  // Perform URL scan
  fetch(apiUrl, options)
    .then(response => response.json())
    .then(response => {
      const analysisId = response.data.id;
      // Display the results
      displayResults(analysisId);
    })
    .catch(err => console.error(err));
}

function displayResults(analysisId) {
  const resultContainer = document.getElementById('resultContainer');
  const resultsElement = document.getElementById('scanResults');
  const apiUrl = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;

  // Fetch analysis results
  fetch(apiUrl, {
    method: 'GET',
    headers: { 'x-apikey': apiKey, 'accept': 'application/json' }
  })
    .then(response => response.json())
    .then(response => {
      // Display the analysis results
      resultsElement.textContent = JSON.stringify(response, null, 2);
      resultContainer.style.display = 'block';
    })
    .catch(err => console.error(err));
}