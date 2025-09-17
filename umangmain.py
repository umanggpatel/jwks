#Umang Patel CSCE3550 Project1
from cryptography.hazmat.primitives.asymmetric import rsa as myrsa
from cryptography.hazmat.primitives import serialization as serial
import base64 as b64
from http.server import BaseHTTPRequestHandler as handler, HTTPServer as server
from datetime import datetime, timedelta, timezone
import jwt
from urllib.parse import urlparse as urlp, parse_qs as parqs
import json

host= "127.0.0.1"#localhost 
port=8080#portnumber

# Encode RSA integer to Base64URL string for JWKS JSON
def encoded_base64(number):
    b=number.to_bytes((number.bit_length()+7)//8,'big')
    return b64.urlsafe_b64encode(b).rstrip(b'=').decode()

privatekey=myrsa.generate_private_key (key_size=2048,public_exponent=65537)
expiredkey=myrsa.generate_private_key(key_size=2048,public_exponent=65537)
priv_num=privatekey.private_numbers()

active_pem, inactive_pem =[
    key_object.private_bytes(
        encoding=serial.Encoding.PEM,format=serial.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serial.NoEncryption()
    )
    for key_object in (privatekey, expiredkey)
] 
#class having all methods to handle HTTP services
class AuthService(handler):
    def reject(self):
        self.send_response(405)
        self.end_headers()

    do_HEAD = do_DELETE = do_PUT = do_PATCH = reject  # Reject (Error 405) unsupported HTTP methods for JWKS server

#Handles GET requests and serves JWKS contaninng public keys
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            pub = priv_num.public_numbers
            data = {"keys": [{"alg": "RS256", "kty": "RSA", "use": "sig", "kid": "goodKID", "n": encoded_base64(pub.n), "e": encoded_base64(pub.e)}]}
            self.wfile.write(json.dumps(data).encode())
        else:
            self.reject()
    #Handles POST requests to /auth and issue JWTs
    def do_POST(self):
        parsed = urlp(self.path)
        if parsed.path != "/auth":
            return self.reject()

        expired = 'expired' in parqs(parsed.query)
        headers = {"kid": "expiredKID" if expired else "goodKID"}
        payload = {
            "user": "username",
            "exp": datetime.now(timezone.utc) + (-timedelta(hours=1) if expired else timedelta(hours=1))
        }
        key = inactive_pem if expired else active_pem
        token = jwt.encode(payload, key, algorithm="RS256", headers=headers)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(token.encode())
    #Function to start and run the server
def run_server():
    webserver = server((host, port), AuthService)
    print(f"The server is active")
    try:
        webserver.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        webserver.server_close()
run_server()
""""
For this assignment I used AI tools such as ChatGPT to some extent, mainly to understand the concept, fix some errors, and get suggestiona on how the code could improved. This was for learning purpose and the prompts used with my code were:
Which Python libraries are useful for building a server like this?
How can I structure this server code better?
What can I add next to improve this part of the code?
How can I implement key expiry properly?
"""