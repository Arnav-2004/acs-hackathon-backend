# SHIELDX - Backend

This project is a Flask-based web application designed to provide security insights and vulnerability analysis by scraping data from various sources, including CVE details and security news websites. It also integrates with MongoDB for user management and Google's Gemini API for generating security insights.

## Features

- **User Authentication**: Signup, login, and update user details.
- **Security Scans**: Check for missing security headers, open directories, and exposed JS files.
- **Vulnerability Analysis**: Scrape and analyze CVE data by date, type, impact, and known exploited vulnerabilities.
- **News Scraping**: Fetch the latest security news from The Hacker News.
- **Insights Generation**: Use Google's Gemini API to generate security insights based on scan results.

## Prerequisites

- Python 3.x
- MongoDB
- Google Gemini API Key
- Flask
- BeautifulSoup
- Requests
- Flask-CORS
- PyMongo
- python-dotenv

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/Arnav-2004/acs-hackathon-backend.git
   cd acs-hackathon-backend
   ```

2. **Create a virtual environment**:

   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**:
   Create a `.env` file in the root directory and add the following variables:

   ```plaintext
   MONGO_URI=mongodb://localhost:27017/
   GEMINI_API_KEY=your_gemini_api_key
   ```

5. **Run the application**:
   ```bash
   python app.py
   ```

## API Endpoints

### User Management

- **Signup**: `POST /signup`

  - Request Body:
    ```json
    {
      "username": "user123",
      "email": "user@example.com",
      "password": "password123"
    }
    ```
  - Response:
    ```json
    {
      "message": "User created successfully"
    }
    ```

- **Login**: `POST /login`

  - Request Body:
    ```json
    {
      "email": "user@example.com",
      "password": "password123"
    }
    ```
  - Response:
    ```json
    {
      "message": "Login successful",
      "username": "user123"
    }
    ```

- **Update User**: `PUT /update-user`
  - Request Body:
    ```json
    {
      "username": "user123",
      "new_username": "newuser123",
      "new_email": "newuser@example.com",
      "new_password": "newpassword123"
    }
    ```
  - Response:
    ```json
    {
      "message": "User updated successfully"
    }
    ```

### Vulnerability Analysis

- **Scrape by Date**: `GET /scrape-by-date/<int:year>`

  - Response:
    ```json
    {
      "0": {
        "cveid": "CVE-2023-1234",
        "summary": "A vulnerability in...",
        "source": "NVD",
        "maxcvss": "9.8",
        "epssscore": "0.95",
        "publisheddate": "2023-01-01",
        "updateddate": "2023-01-02",
        "link": "https://www.cvedetails.com/cve/CVE-2023-1234"
      },
      ...
    }
    ```

- **Number of CVEs by Year**: `GET /no-of-cves-by-year`

  - Response:
    ```json
    {
      "2023": "12345",
      "2022": "9876",
      ...
    }
    ```

- **Scrape by Type**: `GET /scrape-by-type`

  - Response:
    ```json
    {
      "2023": {
        "Vulnerability Type": "XSS",
        "Count": "123"
      },
      ...
    }
    ```

- **Scrape by Impact Types**: `GET /scrape-by-impact-types`

  - Response:
    ```json
    {
      "2023": {
        "Impact Type": "High",
        "Count": "456"
      },
      ...
    }
    ```

- **Scrape Known Exploited**: `GET /scrape-known-exploited/<int:year>`
  - Response:
    ```json
    {
      "0": {
        "cveid": "CVE-2023-1234",
        "summary": "A vulnerability in...",
        "source": "NVD",
        "maxcvss": "9.8",
        "epssscore": "0.95",
        "publisheddate": "2023-01-01",
        "updateddate": "2023-01-02",
        "cisakevadded": "2023-01-03"
      },
      ...
    }
    ```

### News Scraping

- **Scrape News**: `GET /scrape-news`
  - Response:
    ```json
    {
      "0": {
        "title": "New Vulnerability Discovered",
        "description": "A new vulnerability has been discovered...",
        "link": "https://thehackernews.com/2023/01/new-vulnerability-discovered.html"
      },
      ...
    }
    ```

### Insights Generation

- **Generate Insights**: `POST /generate-insights`
  - Request Body:
    ```json
    {
      "url": "https://example.com",
      "options": "security headers"
    }
    ```
  - Response:
    ```json
    {
      "insights": "The website is missing critical security headers..."
    }
    ```

## Acknowledgments

- [CVE Details](https://www.cvedetails.com) for providing CVE data.
- [The Hacker News](https://thehackernews.com) for security news.
- [Google Gemini](https://gemini.google.com) for AI-powered insights.
