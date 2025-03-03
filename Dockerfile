FROM python:3.9

RUN apt-get update && apt-get install -y \
    nmap \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Flask app
COPY . .

# Start the application
CMD ["gunicorn", "-b", "0.0.0.0:5000", "main:app"]
