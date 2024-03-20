import os
import re
import requests
from flask import Flask, render_template, request, jsonify
import json
from bs4 import BeautifulSoup
import ipaddress
from urllib.parse import urlparse
from OTXv2 import OTXv2, IndicatorTypes, NotFound

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

VIRUSTOTAL_API_KEY = "3cafe6ff9ae09edcb22bd5529609efc1eca8209943277c80ab99cd70a4cf684f"  # Replace with your actual VirusTotal API key
ZENROWS_API_KEY = "ef590a641c3eaa284b8086a70872c2d971a72154"  # Replace with your actual Zenrows API key
otx = OTXv2("e382cd19bff4ec2a3b48c8e5e060daac982a584b7ddd11ddba7ca283d8eba5c2") # Replace with your actual OTX API key

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
        match = re.search(r'-(.*?)-', scan_results['data']['id'])
        if match:
            extracted_id = match.group(1)
            print(extracted_id)
            reAnalyzeURL = f"https://www.virustotal.com/api/v3/urls/{extracted_id}/analyse"

            headers = {
                "accept": "application/json",
                "x-apikey": VIRUSTOTAL_API_KEY
            }
            response = requests.post(reAnalyzeURL, headers=headers)
        print("Scan Results: ", scan_results)
        return scan_results
    else:
        return {"error": f"Failed to scan URL. Status code: {response.status_code}"}

@app.route('/get_community_comments', methods=['GET'])
def get_community_comments():
    analysis_id = request.args.get('analysisId')

    #print("Analysis ID for Community Comments: ", analysis_id)

    if not analysis_id:
        return {"error": "Analysis ID parameter is missing."}

    url = f"https://www.virustotal.com/api/v3/urls/{analysis_id}/comments?limit=10"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
    }
    response = requests.get(url, headers=headers)

    #print("URL to grab comments from: ", url)

    if response.status_code == 200:
        #print("response.json: ", response.json())
        community_comments = response.json()
        return jsonify(community_comments)
    else:
        return {"error": f"Failed to fetch community comments. Status code: {response.status_code}"}

@app.route('/get_reference_url', methods=['GET'])
def get_reference_url():
    # Get the URL parameter from the request
    url = request.args.get('url')

    # Ensure the URL parameter is present
    if not url:
        return {"error": "URL parameter is missing."}
    
    params = {
        'url': url,
        'apikey': ZENROWS_API_KEY,
        'js_render': 'true',
        'wait': '2500',
    }
    zenrows_url = 'https://api.zenrows.com/v1/'

    try:
        response = requests.get(zenrows_url, params=params)

        if response.status_code == 200:
            # Parse HTML content using BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all list items containing URL links
            url_list_items = soup.find_all('li')
            reference_url = None

            for item in url_list_items:
                # Find anchor tag within list item
                anchor_tag = item.find('a')
                if anchor_tag and anchor_tag.has_attr('href'):
                    # Extract the URL link
                    reference_url = anchor_tag['href']
                    break  # Exit the loop after finding the first URL

            if reference_url:
                print(reference_url)
                return jsonify({'reference_url': reference_url})
            else:
                return {"error": "No reference URLs found."}

        else:
            return {"error": f"Failed to fetch page. Status code: {response.status_code}"}

    except requests.exceptions.RequestException as e:
        return {"error": f"Request to the URL failed: {e}"}

@app.route('/get_zenrows_google', methods=['GET'])
def searchReferenceViaGoogle():
    # Get the URL parameter from the request
    url = request.args.get('url')

    # Ensure the URL parameter is present
    if not url:
        return {"error": "URL parameter is missing."}

    params = {
        'url': url,
        'apikey': ZENROWS_API_KEY,
        'premium_proxy': 'true',
        'autoparse': 'true',
    }
    zenrows_url = 'https://api.zenrows.com/v1/'
    try:
        response = requests.get(zenrows_url, params=params)

        if response.status_code == 200:
            response_json = json.loads(response.text)

            # Get the organic results
            organic_results = response_json.get('organic_results', [])

            # Extract the link from the first organic result, if available
            first_link = None
            if organic_results:
                first_link = organic_results[0].get('link')
            return jsonify({'first_link': first_link})
        else:
            return {"error": f"Failed to fetch Zenrows analysis. Status code: {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request to Zenrows API failed: {e}"}

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


def check_input_type(input_str):
    try:
        ipaddress.IPv4Address(input_str)
        return "IPv4 Address"
    except ipaddress.AddressValueError:
        parsed_url = urlparse(input_str)
        if parsed_url.scheme:
            return "Full URL"
        else:
            return "Domain"

@app.route('/search_pulses', methods=['POST'])
def search_pulses():
    IOC = request.json['url']
    input_type = check_input_type(IOC)
    print("Finding pulse for:", IOC)
    try:
        if input_type == "IPv4 Address":
            pulses = otx.get_indicator_details_full(IndicatorTypes.IPv4, IOC)
        elif input_type == "Domain":
            print("Domain")
            pulses = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, IOC)
            if pulses['general']['pulse_info']['count'] == 0:
                pulses = otx.get_indicator_details_full(IndicatorTypes.HOSTNAME, IOC)
        else:
            print("URL")
            pulses = otx.get_indicator_details_full(IndicatorTypes.URL, IOC)
            if pulses['general']['pulse_info']['count'] == 0:
                pulses = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, IOC)
        #print("This is from pulse:", pulses)
        return jsonify({'pulses': pulses})
    except NotFound:  # Catch the specific exception
        if input_type == "IPv4 Address":
            return jsonify({'error': 'Indicator not found'})
        elif input_type == "Domain":
            print("First NotFound (HOSTNAME):", IOC)
            pulses = otx.get_indicator_details_full(IndicatorTypes.HOSTNAME, IOC)
        else:
            IOC = urlparse(IOC).netloc
            print("First NotFound (DOMAIN):", IOC)
            pulses = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, IOC)
            if pulses['general']['pulse_info']['count'] == 0:
                pulses = otx.get_indicator_details_full(IndicatorTypes.HOSTNAME, IOC)
        return jsonify({'pulses': pulses})

if __name__ == '__main__':
    app.run(debug=True)