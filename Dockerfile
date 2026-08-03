FROM python:3.11-slim

# ============================================================
# STEP 1: Install Debian-available system packages
# NOTE: nikto is NOT in Debian repos, installed from GitHub below
# ============================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whois \
    bind9-dnsutils \
    wget \
    perl \
    git \
    gcc \
    libc6-dev \
    ruby \
    libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

# ============================================================
# STEP 2: Build dnsmap from source (single C file in src/)
# ============================================================
RUN git clone --depth 1 https://github.com/resurrecting-open-source-projects/dnsmap.git /tmp/dnsmap \
    && gcc -O2 -o /usr/local/bin/dnsmap /tmp/dnsmap/src/dnsmap.c \
    && chmod +x /usr/local/bin/dnsmap \
    && rm -rf /tmp/dnsmap

# ============================================================
# STEP 3: Install urlcrazy from GitHub
# ============================================================
RUN git clone --depth 1 https://github.com/urbanadventurer/urlcrazy.git /opt/urlcrazy \
    && chmod +x /opt/urlcrazy/urlcrazy \
    && ln -sf /opt/urlcrazy/urlcrazy /usr/local/bin/urlcrazy

# ============================================================
# STEP 4: Install nikto from GitHub (not in Debian repos)
# ============================================================
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# ============================================================
# STEP 5: Python application setup
# ============================================================
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p reports

EXPOSE 5000

ENV FLASK_CONFIG=production
ENV PYTHONUNBUFFERED=1

CMD exec gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 "app:app"
