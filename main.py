from flask import Flask, jsonify, request
from bs4 import BeautifulSoup
import requests
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
import os
from werkzeug.security import generate_password_hash, check_password_hash
import subprocess
from google import genai
from google.genai import types

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Connect to MongoDB
client = MongoClient(os.getenv('MONGO_URI'))
db = client['acshackathon']  # Replace with your database name
users_collection = db['users']  # Collection to store user data

# Headers for web scraping
HEADERS = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}

# Helper function to hash passwords
def hash_password(password):
    return generate_password_hash(password)

# Helper function to verify passwords
def verify_password(hashed_password, password):
    return check_password_hash(hashed_password, password)

# Signup API
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    # Check if the user already exists
    if users_collection.find_one({'username': username}):
        return jsonify({'error': 'Username already exists'}), 400

    # Hash the password
    hashed_password = hash_password(password)

    # Insert the new user into the database
    users_collection.insert_one({
        'username': username,
        'email': email,
        'password': hashed_password
    })

    return jsonify({'message': 'User created successfully'}), 201

# Login API
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    # Find the user in the database
    user = users_collection.find_one({'email': email})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Verify the password
    if not verify_password(user['password'], password):
        return jsonify({'error': 'Invalid password'}), 401

    return jsonify({'message': 'Login successful', 'username': user['username']}), 200

# Update User API
@app.route('/update-user', methods=['PUT'])
def update_user():
    data = request.get_json()
    username = data.get('username')
    new_username = data.get('new_username')
    new_email = data.get('new_email')
    new_password = data.get('new_password')

    if not username:
        return jsonify({'error': 'Username is required to identify the user'}), 400

    # Find the user in the database
    user = users_collection.find_one({'username': username})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Prepare the update payload
    update_payload = {}
    if new_username:
        # Check if the new username already exists
        if users_collection.find_one({'username': new_username}):
            return jsonify({'error': 'New username already exists'}), 400
        update_payload['username'] = new_username
    if new_email:
        # Check if the new email already exists
        if users_collection.find_one({'email': new_email}):
            return jsonify({'error': 'New email already exists'}), 400
        update_payload['email'] = new_email
    if new_password:
        # Hash the new password
        update_payload['password'] = hash_password(new_password)

    # Update the user in the database
    users_collection.update_one({'username': username}, {'$set': update_payload})

    return jsonify({'message': 'User updated successfully'}), 200

# Existing routes for scraping
@app.route('/scrape-by-date/<int:year>', methods=['GET'])
def scrape_by_date_route(year):
    data = scrape_by_date(year)
    return jsonify(data)

@app.route('/no-of-cves-by-year', methods=['GET'])
def no_of_cves_by_year_route():
    data = no_of_cves_by_year()
    return jsonify(data)

@app.route('/scrape-by-type', methods=['GET'])
def scrape_by_type_route():
    data = scrape_by_type()
    return jsonify(data)

@app.route('/scrape-by-impact-types', methods=['GET'])
def scrape_by_impact_types_route():
    data = scrape_by_impact_types()
    return jsonify(data)

@app.route('/scrape-known-exploited/<int:year>', methods=['GET'])
def scrape_known_exploited_route(year):
    data = scrape_known_exploited(year)
    return jsonify(data)

@app.route('/generate-insights', methods=['POST'])
def generate_insights_route():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    insights = generate_insights(url)
    return jsonify({'insights': insights})

# Existing scraping functions
def scrape_by_date(year):
    base_url = f'https://www.cvedetails.com/vulnerability-list/year-{year}/vulnerabilities.html'
    
    res = requests.get(base_url, headers=HEADERS)
    soup = BeautifulSoup(res.text, 'lxml')

    cveinfo_data = {}

    cveinfo = soup.find_all('div', class_="border-top py-3 px-2 hover-bg-light")

    for index, info in enumerate(cveinfo):
        cveid = info.find('h3', class_="col-md-4 text-nowrap").text.strip()
        summary = info.find('div', class_="cvesummarylong py-0").text.strip()
        source = info.find('div', class_="cvelistassigner").text.strip()
        maxcvss = info.find('div', class_="cvssbox").text.strip()
        epssscore = info.find('span', class_="epssbox").text.strip()
        publisheddate = info.find_all('div', class_="row mb-1")[2].text.split("\n")[2].strip()
        updateddate = info.find_all('div', class_="row mb-1")[3].text.split("\n")[2].strip()
        link = f"https://www.cvedetails.com{info.find('a').get('href')}"
        cveinfo_data[index] = {
            'cveid': cveid,
            'summary': summary,
            'source': source,
            'maxcvss': maxcvss,
            'epssscore': epssscore,
            'publisheddate': publisheddate,
            'updateddate': updateddate,
            'link': link
        }
    
    return cveinfo_data

def no_of_cves_by_year():
    base_url = 'https://www.cvedetails.com/browse-by-date.php'
    
    res = requests.get(base_url, headers=HEADERS)
    soup = BeautifulSoup(res.text, 'lxml')
    
    totals_data = {}

    list_groups = soup.find_all('ul', class_='list-group list-group-horizontal-md border-0 rounded-0')
    
    for group in list_groups:
        year_element = group.find('a', href=True)
        if year_element:
            year = year_element.text.strip()
            
            total_element = group.find('div', class_='d-inline p-0 pt-2')
            if total_element:
                total = total_element.text.strip().replace('\xa0', '')
                totals_data[year] = total
    
    return totals_data

def scrape_by_type():
    base_url = 'https://www.cvedetails.com/vulnerabilities-by-types.php'

    res = requests.get(base_url, headers=HEADERS)
    soup = BeautifulSoup(res.text, 'lxml')
    
    table = soup.find('table', class_="stats table table-hover w-auto ms-2")
    
    if not table:
        return {}

    headers = [header.text.strip() for header in table.find('thead').find_all('th')]
    rows = table.find('tbody').find_all('tr')
    
    vulnerability_data = {}

    for row in rows:
        if 'stats-total' in row.get('class', []):
            continue

        year_data = {}
        cells = row.find_all(['th', 'td'])
        
        year = cells[0].text.strip()
        for i in range(1, len(cells)):
            header = headers[i]
            value = cells[i].text.strip()
            year_data[header] = value
        
        vulnerability_data[year] = year_data
    
    return vulnerability_data

def scrape_by_impact_types():
    base_url = 'https://www.cvedetails.com/vulnerabilities-by-types.php'
    
    res = requests.get(base_url, headers=HEADERS)
    soup = BeautifulSoup(res.text, 'lxml')
    
    table = soup.find('table', class_="stats table table-hover w-75")
    
    if not table:
        return {}

    headers = [header.text.strip() for header in table.find('thead').find_all('th')]
    rows = table.find('tbody').find_all('tr')
    
    impact_data = {}

    for row in rows:
        if 'stats-total' in row.get('class', []):
            continue

        year_data = {}
        cells = row.find_all(['th', 'td'])
        
        year = cells[0].text.strip()
        for i in range(1, len(cells)):
            header = headers[i]
            value = cells[i].text.strip()
            year_data[header] = value
        
        impact_data[year] = year_data
    
    return impact_data

def scrape_known_exploited(year):
    base_url = f'https://www.cvedetails.com/vulnerability-list/year-{year}/vulnerabilities.html?page=1&order=6&isInCISAKEV=1'
    
    res = requests.get(base_url, headers=HEADERS)
    soup = BeautifulSoup(res.text, 'lxml')

    cveinfo_data = {}

    cveinfo = soup.find_all('div', class_="border-top py-3 px-2 hover-bg-light")

    for index, info in enumerate(cveinfo):
        cveid = info.find('h3', class_="col-md-4 text-nowrap").text.strip()
        summary = info.find('div', class_="cvesummarylong py-0").text.strip()
        source = info.find('div', class_="cvelistassigner").text.strip()
        maxcvss = info.find('div', class_="cvssbox").text.strip()
        epssscore = info.find('span', class_="epssbox").text.strip()
        publisheddate = info.find_all('div', class_="row mb-1")[2].text.split("\n")[2].strip()
        updateddate = info.find_all('div', class_="row mb-1")[3].text.split("\n")[2].strip()
        cisakevadded = info.find('div', class_="col-md-3").find('div', string="CISA KEV Added").find_next_sibling('div').text.strip()
        cveinfo_data[index] = {
            'cveid': cveid,
            'summary': summary,
            'source': source,
            'maxcvss': maxcvss,
            'epssscore': epssscore,
            'publisheddate': publisheddate,
            'updateddate': updateddate,
            'cisakevadded': cisakevadded
        }
    
    return cveinfo_data

def generate(input):
    client = genai.Client(
        api_key=os.getenv("GEMINI_API_KEY"),
    )

    model = "gemini-2.0-flash"
    contents = [
        types.Content(
            role="user",
            parts=[
                types.Part.from_text(
                    text=f"""
                    Analyze the following network scan results and provide actionable insights for the user. Focus on identifying potential vulnerabilities, security risks, and any exposed services. For each issue identified, provide a brief explanation of the risk and recommend steps to mitigate or fix the issue. Be concise and prioritize the most critical issues.

                    Scan Results:
                    {input}

                    Instructions:
                    1. Identify open ports, services, and their versions.
                    2. Highlight any known vulnerabilities associated with the services.
                    3. Suggest actionable steps to secure the system (e.g., close unnecessary ports, update software, apply patches).
                    4. If no critical issues are found, state that the system appears secure but recommend general best practices for hardening.

                    Output Format:
                    - **Issue**: [Description of the issue]
                      **Risk**: [Explanation of the risk]
                      **Recommendation**: [Steps to fix or mitigate the issue]

                    Example:
                    - **Issue**: Port 22 (SSH) is open.
                      **Risk**: Exposes the system to brute-force attacks if weak credentials are used.
                      **Recommendation**: Use strong passwords or SSH keys, disable root login, and consider using a non-standard port.

                    Provide only the insights and recommendations. Do not include unnecessary details or explanations.
                    """
                ),
            ],
        ),
    ]
    generate_content_config = types.GenerateContentConfig(
        temperature=1,
        top_p=0.95,
        top_k=40,
        max_output_tokens=8192,
        response_mime_type="text/plain",
    )

    final_message = ""
    for chunk in client.models.generate_content_stream(
        model=model,
        contents=contents,
        config=generate_content_config,
    ):
        final_message += chunk.text

    return final_message

def generate_insights(url):
    # This function will run some common attacks on the provided URL and generate insights
    insights = {}

    # Run a port scan using nmap
    port_scan_result = subprocess.run(['nmap', '-sS', url], capture_output=True, text=True)
    insights['port_scan'] = port_scan_result.stdout

    # Run a UDP scan using nmap
    udp_scan_result = subprocess.run(['nmap', '-sU', url], capture_output=True, text=True)
    insights['udp_scan'] = udp_scan_result.stdout

    # Run a ping scan
    # ping_result = subprocess.run(['ping', '-c', '4', url], capture_output=True, text=True)
    # insights['ping'] = ping_result.stdout

    # Here you can add more scans or attacks as needed
    data = generate(insights)

    return data
    

if __name__ == '__main__':
    app.run(debug=True)