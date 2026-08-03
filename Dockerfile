FROM python:3.11-slim

# Install system binaries required by NMAP-X security tools:
# nmap, dnsmap, urlcrazy, whois, bind9-dnsutils (dig), wget, nikto, perl
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsmap \
    urlcrazy \
    whois \
    bind9-dnsutils \
    wget \
    nikto \
    perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependencies and install Python packages (Flask, Gunicorn, DNSRecon, Wafw00f, BeautifulSoup, lxml, rich)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy remaining application code
COPY . .

# Ensure reports directory exists
RUN mkdir -p reports

# Expose default port
EXPOSE 5000

# Default environment configuration
ENV FLASK_CONFIG=production
ENV PYTHONUNBUFFERED=1

# Run the app using Gunicorn, respecting $PORT set by cloud providers like Render
CMD exec gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 "app:app"
