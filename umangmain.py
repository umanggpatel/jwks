#Umang Patel CSCE3550 Project1
from cryptography.hazmat.primitives.asymmetric import rsa as myrsa
from cryptography.hazmat.primitives import serialization as serial
import base64 as b64
from http.server import BaseHTTPRequestHandler as handler, HTTPServer as server

host= "127.0.0.1"
port=8080


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

class AuthService(handler):
    def reject(self):
        self.send_response(405)
        self.end_headers()

    do_HEAD = do_DELETE = do_PUT = do_PATCH = reject



