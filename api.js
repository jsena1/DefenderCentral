const apiKey = "634ffd627bc709bea9cae729a794c44482bb5b0381818e1acd076d4d38886da6"
const openaiApiKey = "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";
const url = 'https://api.openai.com/v1/chat/completions';

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

// Function to send user query to ChatGPT
/*function chatWithGPT() {
  const userInput = document.getElementById('chatInput').value;
  const apiUrl = 'https://api.openai.com/v1/models';
  const options = {
      method: 'POST',
      headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openaiApiKey}`
      },
      body: JSON.stringify({
          model: 'davinci', // You can choose different models based on your requirements
          prompt: userInput,
          max_tokens: 150 // Adjust max_tokens based on the length of the expected response
      })
  };

  fetch(apiUrl, options)
      .then(response => {
          if (!response.ok) {
              throw new Error('Network response was not ok');
          }
          return response.json();
      })
      .then(data => {
          const chatResults = document.getElementById('chatResults');
          if (data.choices && data.choices.length > 0) {
              chatResults.innerHTML = data.choices[0].text.trim();
          } else {
              chatResults.innerHTML = "No response from the model";
          }
      })
      .catch(err => console.error(err));
}*/

async function chatWithGPT(){
    const response = await fetch(url,{
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${openaiApiKey}`
      },
      body: JSON.stringify({
        messages: [{role: "user", content: "Tell me a joke"}],
        temperature: 0.6,
        model: "gpt-3.5-turbo",
        max_tokens: 30,
      })
    })
console.log(await response.json());
}