import os
import re
import requests
from flask import Flask, render_template, request, jsonify
import json
import ipaddress
from urllib.parse import urlparse
import nltk
from newspaper import Article

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

VIRUSTOTAL_API_KEY = "3cafe6ff9ae09edcb22bd5529609efc1eca8209943277c80ab99cd70a4cf684f"  # Replace with your actual VirusTotal API key

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
    print("Finish Scan")

    if response.status_code == 200:
        print("rescan")
        scan_results = response.json()
        match = re.search(r'-(.*?)-', scan_results['data']['id'])
        '''
        if match:
            extracted_id = match.group(1)
            print(extracted_id)
            reAnalyzeURL = f"https://www.virustotal.com/api/v3/urls/{extracted_id}/analyse"

            headers = {
                "accept": "application/json",
                "x-apikey": VIRUSTOTAL_API_KEY
            }
            response = requests.post(reAnalyzeURL, headers=headers)
        '''
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

@app.route('/get_reference_data', methods=['GET'])
def get_reference_data():
    # Get the URL parameter from the request
    url = request.args.get('url')

    # Ensure the URL parameter is present
    if not url:
        return {"error": "URL parameter is missing."}

    try:
        article = Article(url, language = "en")
        article.download()
        article.parse()
        article.nlp()
        return jsonify({'relevant_info': article.text})

    except requests.exceptions.RequestException as e:
        return {"error": f"Request to Zenrows API failed: {e}"}

def check_input_type(input_str):
    try:
        ipaddress.IPv4Address(input_str)
        return "IPv4"
    except ipaddress.AddressValueError:
        parsed_url = urlparse(input_str)
        if parsed_url.scheme:
            return "url"
        else:
            return "domain"

def DomainToHostname_pulse(IOC):
    print("Domain -> Hostname:", IOC)
    url = f"https://otx.alienvault.com/api/v1/indicator/hostname/{IOC}/general"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        pulses = data["pulse_info"]["pulses"]
        if pulses:
            return print_references(pulses)
        else:
            return "No Reference"
    else:
        return "No Reference"

def UrlToDomain_pulse(IOC):
    IOC = urlparse(IOC).netloc
    print("URL -> Domain:", IOC)
    url = f"https://otx.alienvault.com/api/v1/indicator/domain/{IOC}/general"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        pulses = data["pulse_info"]["pulses"]
        if pulses:
            return print_references(pulses)
        else:
            return DomainToHostname_pulse(IOC)
    else:
        return DomainToHostname_pulse(IOC)

def print_references(pulses):
    found_AlienVault = False
    found_CyberHunter_NL = False
    found_CyberHunterAutoFeed = False
    found_tr2222200 = False
    references = {"AlienVault": [], "CyberHunter_NL": [], "CyberHunterAutoFeed": [], "tr2222200": []}
    for pulse in pulses:
        username = pulse["author"]["username"]
        if username == "AlienVault" and not found_AlienVault:
            references[username].extend(pulse["references"])
            found_AlienVault = True
        elif username == "CyberHunter_NL" and not found_CyberHunter_NL:
            references[username].extend(pulse["references"])
            found_CyberHunter_NL = True
        elif username == "tr2222200" and not found_tr2222200:
            references[username].extend(pulse["references"])
            found_tr2222200 = True
        elif username == "CyberHunterAutoFeed" and not found_CyberHunterAutoFeed:
            references[username].extend(pulse["references"])
            found_CyberHunterAutoFeed = True
    if found_AlienVault:
        #print("Username: AlienVault")
        return references["AlienVault"][0]

    if not found_AlienVault and found_CyberHunter_NL:
        #print("Username: CyberHunter_NL")
        return references["CyberHunter_NL"][0]

    if not found_AlienVault and not found_CyberHunter_NL and found_tr2222200:
        return references["tr2222200"][0]

    if not found_AlienVault and not found_CyberHunter_NL and not found_tr2222200 and  found_CyberHunterAutoFeed:
        #print("Username: CyberHunterAutoFeed")
        return references["CyberHunterAutoFeed"][0]
    else:
        return "No Reference"

@app.route('/search_pulses', methods=['POST'])
def search_pulses():
    IOC = request.json['url']

    indicatorType = check_input_type(IOC)
    url = f"https://otx.alienvault.com/api/v1/indicator/{indicatorType}/{IOC}/general"
    print(url)
    response = requests.get(url)
    if response.status_code == 200:
        print("Passed URL")
        data = response.json()
        pulses = data["pulse_info"]["pulses"]
        if pulses:
            return print_references(pulses)
        else:
            return UrlToDomain_pulse(IOC)
    else:
        if indicatorType == "IPv4":
            return "No Reference"
        elif indicatorType == "domain":
            return DomainToHostname_pulse(IOC)
        else:
            return UrlToDomain_pulse(IOC)

if __name__ == '__main__':
    app.run(debug=True)