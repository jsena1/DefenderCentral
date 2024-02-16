
function scan(){
  //
  const urlToCheck= 
  const options = {method: 'GET', headers: {accept: 'application/json','x-apikey': 'cb229d4eedbd098dc17c96487ca808a16b1d1e0d4a013016bcb9f7861f245360' }};

  fetch('https://www.virustotal.com/api/v3/urls/id', options)
    .then(response => response.json())
    .then(response => console.log(response))
    .catch(err => console.error(err));

};