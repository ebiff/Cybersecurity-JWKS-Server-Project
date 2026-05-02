"""JWKS Server with AES encryption and sqlite database for key storage"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import sqlite3
import os
import uuid
import argon2
import time
import base64
import json
import datetime
import jwt
from pyrate_limiter import Limiter, Rate, Duration, InMemoryBucket
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


HOST_NAME = "localhost"
SERVER_PORT = 8080
load_dotenv()  # Load environment variables from .env file

#Rate limiter setup - limit to 10 authentication requests per second
rate = Rate(10, Duration.SECOND)
bucket = InMemoryBucket([rate])
limiter = Limiter(bucket)

#configure argon2 parameters
ph = argon2.PasswordHasher(time_cost=2, memory_cost=65536, parallelism=4, hash_len=16, salt_len=16)

#Database setup
#connect to/create database file
con = sqlite3.connect('totally_not_my_privateKeys.db')
#database cursor for executing statements and fetching results
cur = con.cursor()
#make table for storing keys
cur.execute("CREATE TABLE IF NOT EXISTS keys(" \
                "kid INTEGER PRIMARY KEY AUTOINCREMENT, " \
                "key BLOB NOT NULL, " \
                "exp INTEGER NOT NULL" \
                ")")
#make table for storing nonces
cur.execute("CREATE TABLE IF NOT EXISTS nonces(" \
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " \
                "nonce TEXT NOT NULL, " \
                "kid INTEGER NOT NULL, " \
                "FOREIGN KEY(kid) REFERENCES keys(kid))")
#make table for users
cur.execute("CREATE TABLE IF NOT EXISTS users(" \
                "id INTEGER PRIMARY KEY AUTOINCREMENT," \
                "username TEXT NOT NULL UNIQUE," \
                "password_hash TEXT NOT NULL," \
                "email TEXT UNIQUE," \
                "date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP," \
                "last_login TIMESTAMP      " \
                ")")
#make table for authentication requests
cur.execute("CREATE TABLE IF NOT EXISTS auth_logs(" \
    "id INTEGER PRIMARY KEY AUTOINCREMENT," \
    "request_ip TEXT NOT NULL," \
    "request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP," \
    "user_id INTEGER," \
    "FOREIGN KEY(user_id) REFERENCES users(id));")

def gen_rsa_key():
    """Generate a new RSA private key and return it in PEM format"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem

def validate_aes_key(key):
    """Validate the AES key from environment variables"""
    if key is None:
        print("AES key not found in environment variables")
        return ValueError("AES key not found")
    elif len(key) != 32:
        print("AES key must be 32 bytes long")
        return ValueError("AES key must be 32 bytes")

def encrypt_aes(key):
    """Encrypt a key using AES encryption with the AES key from NOT_MY_KEY environment variable"""
    aes_key = os.getenv("NOT_MY_KEY").encode()
    validate_aes_key(aes_key)
    nonce = os.urandom(16)  # Generate a random nonce
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    encrypted_private_key = encryptor.update(key) + encryptor.finalize()
    return (encrypted_private_key, nonce)

def decrypt_aes(key, kid):
    """Decrypt an AES-encrypted key using the AES key from NOT_MY_KEY environment variable"""
    cur.execute("SELECT nonce FROM nonces WHERE kid = ?", (kid,))
    nonce = cur.fetchone()[0]
    aes_key = os.getenv("NOT_MY_KEY").encode()
    validate_aes_key(aes_key)
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    decrypted_private_key = decryptor.update(key) + decryptor.finalize()
    return decrypted_private_key

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def cur_time():
    """Get current time as UNIX timestamp"""
    return datetime.datetime.now().timestamp()


def timestamp_to_sql_time(timestamp):
    """Convert a UNIX timestamp to a SQL-compatible datetime string"""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

def store_key_in_db(key, exp):
    """Encrypt a PEM key and store it in the database with an expiration time"""
    encrypted_key, aes_nonce = encrypt_aes(key)
    cur.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_key, exp))
    con.commit()
    cur.execute("SELECT kid FROM keys WHERE key = ?", (encrypted_key,))
    kid = cur.fetchone()[0]
    cur.execute("INSERT INTO nonces (nonce, kid) VALUES (?, ?)", (aes_nonce, kid))
    con.commit()
    return encrypted_key, kid
#generate two keys, one that will be valid and one that will be expired for testing
pem = gen_rsa_key()
expired_pem = gen_rsa_key()

#store encrypted keys in database with expiration times
store_key_in_db(pem, int(cur_time()) + 3600) #valid for 1 hour
store_key_in_db(expired_pem, int(cur_time()) - 3600) #expired 1 hour ago

#sample numbers for testing without database
#numbers = private_key.private_numbers()




class MyServer(BaseHTTPRequestHandler):
    """Custom HTTP request handler for the JWKS server"""
    #set up rate limiter for authentication endpoint
    def do_PUT(self):
        """Handle PUT requests - not allowed for this server"""
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        """Handle PATCH requests - not allowed for this server"""
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        """Handle DELETE requests - not allowed for this server"""
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        """Handle HEAD requests - not allowed for this server"""
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        """Handle POST requests - only /auth and /register endpoints are allowed"""
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            # Rate limit authentication requests by client IP
            success = limiter.try_acquire("auth", blocking=False)
            if not success:
                self.send_response(429)
                self.end_headers()
                self.wfile.write(b"Too many authentication requests - please try again later")
                return
            else:
                #log authentication request to database
                client_ip = self.address_string()
                request_time = timestamp_to_sql_time(cur_time())
                login_info = json.loads(self.rfile.read(int(self.headers['Content-Length']))) 
                username = login_info["username"]
                password = login_info["password"]
                #get user id and password hash to verify password and log authentication attempt
                cur.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
                user_data = cur.fetchone()
                if user_data is None:
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"Invalid username or password")
                    cur.execute("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)", (client_ip, request_time, -1))
                    con.commit()
                    return
                user_id, password_hash = user_data
                try:
                    ph.verify(password_hash, password)
                except argon2.exceptions.VerifyMismatchError:
                    self.send_response(401)
                    self.end_headers()
                    cur.execute("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)", (client_ip, request_time, -1))
                    con.commit()
                    self.wfile.write(b"Invalid username or password")
                    return
                cur.execute("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)", (client_ip, request_time, user_id))
                cur.execute("UPDATE users SET last_login = ? WHERE id = ?", (timestamp_to_sql_time(cur_time()), user_id))
                con.commit()
                user_id = None
                print(f"Authentication request from {client_ip} at {timestamp_to_sql_time(cur_time())} from ")

                headers = {
                    "kid": "goodKID"
                }
                token_payload = {
                    "user": "username",
                    "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
                }
                #if expired, mark jwt as expired and use expired key, otherwise use valid key
                if 'expired' in params:
                    headers["kid"] = "expiredKID"
                    dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
                    token_payload["exp"] = dt
                    #get expired key from database
                    cur.execute("SELECT kid, key FROM keys WHERE exp <= ?", (int(cur_time()),))
                    kid, encrypted_private_key = cur.fetchone()
                    key = decrypt_aes(encrypted_private_key, kid)
                else:
                    #get valid key from database and encode jwt
                    cur.execute("SELECT kid, key FROM keys WHERE exp > ?", (int(cur_time()),))
                    kid, encrypted_private_key= cur.fetchone()
                    key = decrypt_aes(encrypted_private_key, kid)
                encoded_jwt = jwt.encode(token_payload, key, algorithm="RS256", headers=headers)
                self.send_response(200)
                self.send_header("Content-type", "application/jwt")
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
                return


        if parsed_path.path == "/register":
            # Handle user registration
            # Read and parse JSON body
            new_user = json.loads(self.rfile.read(int(self.headers['Content-Length']))) 
            if "username" not in new_user or "email" not in new_user:
                print("Missing username or email in registration request")
                self.send_response(400)
                self.end_headers()
                return
            new_password = str(uuid.uuid4()) #Generate random UUID4 password
            #Print generated password to console for testing
            print(f"Generated password for {new_user['username']}: {new_password}")
            password_hash = ph.hash(new_password) #Hash the password with argon2
            try:
                cur.execute("INSERT INTO users " \
                            "(username, password_hash, email, last_login) " \
                            "VALUES (?, ?, ?, ?)",
                            (new_user["username"], \
                             password_hash, new_user["email"], \
                                timestamp_to_sql_time(cur_time())))
                con.commit()
            except sqlite3.IntegrityError:
                print("Username already exists in database")
                self.send_response(400)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"message": "User registered successfully", "password": new_password}).encode("utf-8"))
            return
        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        """Handle GET requests - only /jwks endpoint is allowed"""
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            cur.execute("SELECT kid, key FROM keys WHERE exp > ? LIMIT 1", (int(cur_time()),))
            pem_keys = cur.fetchall()
            pem_keys = [decrypt_aes(key[1], key[0]) for key in pem_keys]
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
            for key in pem_keys:
                #decode pem from database
                decoded_key = serialization.load_pem_private_key(key, password=None)
                #extract numbers from private key
                nums = decoded_key.private_numbers()
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
    con.close()
    web_server.server_close()
