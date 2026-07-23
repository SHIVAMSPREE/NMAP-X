# NMAP-X Reconnaissance & Web Scanning Platform

A modular, secure Flask-based web application for network reconnaissance, domain enumeration, and web footprinting.

## Features & Architecture

- **Dark Cyber Aesthetic**: High-contrast UI with neon red glowing accents, styled navigation bar, terminal diagnostic windows, and operational dashboard metrics.
- **Modular Design**: Application factory pattern separating core routes, database models, scan modules, and background async services.
- **Security Scope Guardrails**: Strict target input sanitization to prevent unauthorized scanning or command injections.

## Quickstart

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the platform locally:
   ```bash
   python app.py
   ```

3. Access the dashboard:
   Navigating to `http://127.0.0.1:5000/dashboard` in your browser.

## Testing

Run unit & route integration tests:
```bash
pytest
```
