FROM python:3.11-slim

# Install system build tools and base security binaries available in Debian repos
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whois \
    bind9-dnsutils \
    wget \
    nikto \
    perl \
    git \
    gcc \
    make \
    ruby \
    ruby-dev \
    && rm -rf /var/lib/apt/lists/*

# Compile and install dnsmap binary from official source repository
RUN git clone https://github.com/resurrecting-open-source-projects/dnsmap.git /tmp/dnsmap \
    && gcc -O2 /tmp/dnsmap/dnsmap.c -o /usr/local/bin/dnsmap \
    && chmod +x /usr/local/bin/dnsmap \
    && rm -rf /tmp/dnsmap

# Install urlcrazy via RubyGems with git clone fallback
RUN gem install urlcrazy || (git clone https://github.com/urbanadventurer/urlcrazy.git /opt/urlcrazy && ln -s /opt/urlcrazy/urlcrazy /usr/local/bin/urlcrazy)

WORKDIR /app

# Copy requirements and install Python packages (Flask, Gunicorn, DNSRecon, Wafw00f, lxml, rich, etc.)
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
