#Umang Patel CSCE3550 Project2
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64, sqlite3, json, jwt, os
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qs

# Server configuration: host, port, and database file path.
HOST = "127.0.0.1"
PORT = 8080
DB_FILE = "totally_not_my_privateKeys.db"

# Fetches a single key (expired or valid) or all valid keys from the database.

def init_db():    
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_key(key_pem: str, exp_ts: int):
    """Save a key using a parameterized query."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO keys(key, exp) VALUES (?, ?)", (key_pem, exp_ts))
    conn.commit()
    conn.close()

# Fetches a single key (expired or valid) or all valid keys from the database.
def read_key(expired=False):
    now = int(datetime.now(timezone.utc).timestamp())
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    if expired:
        cur.execute("SELECT key FROM keys WHERE exp <= ? LIMIT 1", (now,))
    else:
        cur.execute("SELECT key FROM keys WHERE exp > ? LIMIT 1", (now,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None
def read_valid_keys():
    now = int(datetime.now(timezone.utc).timestamp())
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT key FROM keys WHERE exp > ?", (now,))
    rows = [r[0] for r in cur.fetchall()]
    conn.close()
    return rows

# Encode RSA integer to Base64URL string for JWKS JSON
def encoded_base64(num):
    b = num.to_bytes((num.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def generate_and_store_keys():
    now = datetime.now(timezone.utc)
    pairs = [
        ("expiredKID", now - timedelta(seconds=5)),  
        ("goodKID", now + timedelta(hours=1))        
    ]
    for kid, exp_time in pairs:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        exp_ts = int(exp_time.timestamp())
        save_key(key_pem, exp_ts)


init_db()

conn = sqlite3.connect(DB_FILE)
cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM keys")
count = cur.fetchone()[0]
conn.close()
if count == 0:
    generate_and_store_keys()


# Sends a 405 response for invalid HTTP requests.

class AuthService(BaseHTTPRequestHandler):
    def reject(self):
        self.send_response(405)
        self.end_headers()


    do_HEAD = do_DELETE = do_PUT = do_PATCH = reject
# Handles GET requests and returns the JWKS JSON with valid public keys.
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/.well-known/jwks.json":
            return self.reject()

        valid_keys = read_valid_keys()
        jwks = {"keys": []}
        for pem in valid_keys:
            priv = serialization.load_pem_private_key(pem.encode(), password=None)
            pub = priv.public_key().public_numbers()
            jwks["keys"].append({
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": "goodKID",
                "n": encoded_base64(pub.n),
                "e": encoded_base64(pub.e)
            })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(jwks).encode())


    #Handles POST requests to /auth and issue JWTs
    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/auth":
            return self.reject()

        qs = parse_qs(parsed.query)
        expired = "expired" in qs
        key_pem = read_key(expired)
        if not key_pem:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"No matching key found.")
            return

        private_key = serialization.load_pem_private_key(key_pem.encode(), password=None)
        headers = {"kid": "expiredKID" if expired else "goodKID"}
        payload = {
            "user": "Umang",
            "exp": datetime.now(timezone.utc) + (-timedelta(hours=1) if expired else timedelta(hours=1))
        }
        token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(token.encode())

# Starts the HTTP server and handles requests until stopped.
def run_server():
    webserver = HTTPServer((HOST, PORT), AuthService)
    print(f"Server is active")
    try:
        webserver.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        webserver.server_close()

if __name__ == "__main__":
    run_server()

""""
For this assignment I used AI tools such as ChatGPT to some extent, mainly to understand the concept, fix some errors, and get suggestiona on how the code could improved. This was for learning purpose and the prompts used with my code were:
Which Python libraries are useful for building a server like this?
How can I structure this server code better?
What can I add next to improve this part of the code?
How can I implement key expiry properly?
"""