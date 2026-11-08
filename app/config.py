import os


class Config:
    # VULN-5: Hardcoded fake secrets.
    SECRET_KEY = "fake-secret-key-123"
    API_TOKEN = "fake-api-token-123"
    DB_HOST = os.environ["DB_HOST"]
    DB_PORT = int(os.environ["DB_PORT"])
    DB_NAME = os.environ["DB_NAME"]
    DB_USER = os.environ["DB_USER"]
    DB_PASSWORD = "fake-db-password-123"
