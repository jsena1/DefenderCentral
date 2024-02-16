
function scan(){
  //
  const urlToCheck= 
  const options = {method: 'GET', headers: {accept: 'application/json'}};

  fetch('https://www.virustotal.com/api/v3/urls/id', options)
    .then(response => response.json())
    .then(response => console.log(response))
    .catch(err => console.error(err));

};