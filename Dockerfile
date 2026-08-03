FROM python:3.11-slim

# Install system packages available in Debian repos + build tools
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
    autoconf \
    automake \
    ruby \
    && rm -rf /var/lib/apt/lists/*

# Build dnsmap from source (uses autotools: autogen.sh -> configure -> make)
RUN git clone https://github.com/resurrecting-open-source-projects/dnsmap.git /tmp/dnsmap \
    && cd /tmp/dnsmap \
    && bash autogen.sh \
    && ./configure \
    && make \
    && make install \
    && cd / \
    && rm -rf /tmp/dnsmap

# Install urlcrazy from GitHub (not a published gem)
RUN git clone https://github.com/urbanadventurer/urlcrazy.git /opt/urlcrazy \
    && chmod +x /opt/urlcrazy/urlcrazy \
    && ln -sf /opt/urlcrazy/urlcrazy /usr/local/bin/urlcrazy

WORKDIR /app

# Copy requirements and install Python packages
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
