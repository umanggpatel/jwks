#Umang Patel CSCE3550 Project1
from cryptography.hazmat.primitives.asymmetric import rsa as myrsa

host= "127.0.0.1"
port=8080

privatekey=myrsa.generate_private_key (key_size=2048,public_exponent=65537)
expiredkey=myrsa.generate_private_key(key_size=2048,public_exponent=65537)

