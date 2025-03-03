from flask import Flask, request, jsonify
from bs4 import BeautifulSoup
import json
import requests

app = Flask(__name__)

HEADERS = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}

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
        cveinfo_data[index] = {
            'cveid': cveid,
            'summary': summary,
            'source': source,
            'maxcvss': maxcvss,
            'epssscore': epssscore,
            'publisheddate': publisheddate,
            'updateddate': updateddate
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
        print(cisakevadded)
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

if __name__ == '__main__':
    app.run(debug=True)
