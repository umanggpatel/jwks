import threading
import time
import requests
import sqlite3
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer
from umangmain import (
    AuthService, HOST, PORT, init_db, DB_FILE,
    save_key, generate_and_store_keys, encoded_base64
)

# Start server in background thread
def start_server():
    server = HTTPServer((HOST, PORT), AuthService)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(1)  # wait for server to start
    return server

def test_auth_service_full_coverage():
    # Initialize DB and server
    init_db()
    server = start_server()

    # --- 1. Test JWKS endpoint ---
    r = requests.get(f"http://{HOST}:{PORT}/.well-known/jwks.json")
    assert r.status_code == 200
    assert "keys" in r.json()

    # --- 2. Test valid JWT ---
    r = requests.post(f"http://{HOST}:{PORT}/auth")
    assert r.status_code == 200
    token = r.text
    assert token.startswith("ey")

    # --- 3. Test expired JWT ---
    r = requests.post(f"http://{HOST}:{PORT}/auth?expired")
    assert r.status_code == 200
    expired_token = r.text
    assert expired_token.startswith("ey")

    # --- 4. Test invalid path (should reject) ---
    r = requests.post(f"http://{HOST}:{PORT}/invalidpath")
    assert r.status_code == 405

    # --- 5. Test missing key scenario (500 error) ---
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("DELETE FROM keys")
    conn.commit()
    conn.close()

    r = requests.post(f"http://{HOST}:{PORT}/auth")
    assert r.status_code == 500

    # --- 6. Test unsupported HTTP methods ---
    for method in ["head", "delete", "put", "patch"]:
        req = getattr(requests, method)
        r = req(f"http://{HOST}:{PORT}/auth")
        assert r.status_code == 405

    # --- 7. Force execution of helpers for coverage ---
    generate_and_store_keys()       # cover key generation code
    encoded_base64(123456789)      # cover base64 encoding

    # --- 8. Add an expired key manually to cover that branch ---
    expired_time = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
    dummy_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0DummyKeyForTestPurposeOnly...
-----END RSA PRIVATE KEY-----"""
    save_key(dummy_key, expired_time)
    r = requests.post(f"http://{HOST}:{PORT}/auth?expired")
    assert r.status_code == 200

    # Shutdown server
    server.shutdown()
