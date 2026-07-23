import os
import logging

logger = logging.getLogger("nmap_x.config")

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'nmap-x-cybersecurity-recon-key-31337')
    DEBUG = False
    TESTING = False
    APP_NAME = "NMAP-X Recon Platform"
    VERSION = "1.0.0"
    REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True
    SECRET_KEY = 'test-secret-key'

class ProductionConfig(Config):
    DEBUG = False

    def __init__(self):
        if os.environ.get('SECRET_KEY') is None:
            logger.warning("SECURITY WARNING: Using default fallback SECRET_KEY in Production. Set SECRET_KEY environment variable!")

config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': ProductionConfig
}

