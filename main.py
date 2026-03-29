from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import base64
import json
import datetime
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import sqlite3

HOST_NAME = "localhost"
SERVER_PORT = 8080

#Set up database and table
#connect to/create database file
con = sqlite3.connect('totally_not_my_privateKeys.db')
#database cursor for executing statements and fetching results
cur = con.cursor()
#make table for storing keys
cur.execute("CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)")

#generate keys one valid and one expired for testing
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
private_key2 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

#serialize keys to PEM format
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

#(Question!!) Is this how I set the expiration time? or is it on the actual private key? Or, is it just a boolean of if it is the testing expired key?
#store keys in database with expiration times
cur.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, int(datetime.datetime.now().timestamp()) + 3600))  # valid for 1 hour
cur.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (expired_pem, int(datetime.datetime.now().timestamp())))  # expires now
con.commit()

#sample numbers for testing without database
#numbers = private_key.private_numbers()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
            }
            #if expired mark jwt as expired by setting exp to past time and using expired key, otherwise use valid key
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
                #get expired key from database
                cur.execute("SELECT key FROM keys WHERE exp <= ?", (int(datetime.datetime.now().timestamp()),))
                pem = cur.fetchone()[0]
            else: 
                #get valid key from database and encode jwt
                cur.execute("SELECT key FROM keys WHERE exp > ?", (int(datetime.datetime.now().timestamp()),))
                pem = cur.fetchone()[0]
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.send_header("Content-type", "application/jwt")
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            cur.execute("SELECT key FROM keys WHERE exp > ? LIMIT 1", (int(datetime.datetime.now().timestamp()),))
            pem_keys = cur.fetchall()
            keys = {
                "keys": [
                    #sample key for testing without database
                    # {
                    # "kty": "RSA",
                    # "use": "sig",
                    # "kid": "goodKID",
                    # "alg": "RS256",
                    # "n": int_to_base64(numbers.public_numbers.n),
                    # "e": int_to_base64(numbers.public_numbers.e)
                    # }
                ]
            }
            #convert PEM keys to JWKS format
            for pem in pem_keys:
                #decode pem from database
                private_key = serialization.load_pem_private_key(pem[0], password=None)
                #extract numbers from private key
                nums = private_key.private_numbers()
                #format key data
                key_data = {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "alg": "RS256",
                    "n": int_to_base64(nums.public_numbers.n),
                    "e": int_to_base64(nums.public_numbers.e)
                }
                #add key data to keys list
                keys["keys"].append(key_data)

            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()


if __name__ == "__main__":
    web_server = HTTPServer((HOST_NAME, SERVER_PORT), MyServer)
    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        pass

    web_server.server_close()