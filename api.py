import os
import requests
from flask import Flask, render_template, request, jsonify
from bs4 import BeautifulSoup

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')

VIRUSTOTAL_API_KEY = "3cafe6ff9ae09edcb22bd5529609efc1eca8209943277c80ab99cd70a4cf684f"  # Replace with your actual VirusTotal API key
ZENROWS_API_KEY = "ef590a641c3eaa284b8086a70872c2d971a72154"  # Replace with your actual Zenrows API key

@app.route('/scan_url', methods=['POST'])
def scan_url():
    url = request.form.get('url')
    
    # Perform scanning logic using VirusTotal API
    scan_results = scan_with_virustotal(url)

    return jsonify({'results': scan_results})

@app.route('/get_analysis_report', methods=['GET'])
def get_analysis_report():
    analysis_id = request.args.get('analysisId')

    print("Analysis ID: ", analysis_id)

    if not analysis_id:
        return {"error": "Analysis ID parameter is missing."}

    url = f"https://www.virustotal.com/api/v3/urls/{analysis_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
    }
    response = requests.get(url, headers=headers)

    print("URL Analyzed: ", url)

    if response.status_code == 200:
        analysis_report = response.json()
        return jsonify(analysis_report)
    else:
        return {"error": f"Failed to fetch analysis report. Status code: {response.status_code}"}

def scan_with_virustotal(url):
    virustotal_url = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": url}
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "content-type": "application/x-www-form-urlencoded",
    }
    
    print("URL being scanned: ", url)

    response = requests.post(virustotal_url, data=payload, headers=headers)

    if response.status_code == 200:
        scan_results = response.json()
        print("Scan Results: ", scan_results)
        return scan_results
    else:
        return {"error": f"Failed to scan URL. Status code: {response.status_code}"}

@app.route('/get_community_comments', methods=['GET'])
def get_community_comments():
    analysis_id = request.args.get('analysisId')

    print("Analysis ID for Community Comments: ", analysis_id)

    if not analysis_id:
        return {"error": "Analysis ID parameter is missing."}

    url = f"https://www.virustotal.com/api/v3/urls/{analysis_id}/comments?limit=10"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
    }
    response = requests.get(url, headers=headers)

    print("URL to grab comments from: ", url)

    if response.status_code == 200:
        print("response.json: ", response.json())
        community_comments = response.json()
        return jsonify(community_comments)
    else:
        return {"error": f"Failed to fetch community comments. Status code: {response.status_code}"}

@app.route('/get_zenrows_analysis', methods=['GET'])
def get_zenrows_analysis():
    # Get the URL parameter from the request
    url = request.args.get('url')

    # Ensure the URL parameter is present
    if not url:
        return {"error": "URL parameter is missing."}

    params = {
        'url': url,
        'apikey': ZENROWS_API_KEY,
    }
    zenrows_url = 'https://api.zenrows.com/v1/'
    try:
        response = requests.get(zenrows_url, params=params)

        if response.status_code == 200:
            # Parse HTML content using BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract specific HTML elements (e.g., <p>, <li>, <h1>, <h2>, <h3>)
            extracted_elements = soup.find_all(['p', 'li', 'h1', 'h2', 'h3'])

            # Create a list to store the text content of the extracted elements
            extracted_text = []

            for element in extracted_elements:
                # Get text content of the element
                text_content = element.get_text(strip=True)

                # Split text by <br> and add each part as a separate item in the list
                if '<br>' in text_content:
                    extracted_text.extend(text_content.split('<br>'))
                else:
                    extracted_text.append(text_content)

            # Remove any empty strings from the list
            extracted_text = [item for item in extracted_text if item]

            extracted_string = "\n".join(extracted_text)

            #print("Parsed Extracted HTML Response:\n", extracted_string)

            # Return the extracted text as JSON
            return jsonify({'extracted_text': extracted_text})
        else:
            return {"error": f"Failed to fetch Zenrows analysis. Status code: {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request to Zenrows API failed: {e}"}

if __name__ == '__main__':
    app.run(debug=True)