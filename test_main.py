"""Unit tests for the JWKS server implemented in main.py"""
import threading
import os
import time
from http.server import HTTPServer
import pytest
import requests
import jwt
from main import MyServer, HOST_NAME, SERVER_PORT, decrypt_aes, cur_time, store_key_in_db

@pytest.fixture(scope="module")
def server():
    """Start the server in a separate thread"""
    server_address = (HOST_NAME, SERVER_PORT)
    httpd = HTTPServer(server_address, MyServer)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.daemon = True
    thread.start()

    # Wait for server to start
    base_url = f"http://{HOST_NAME}:{SERVER_PORT}"
    for _ in range(10):
        try:
            requests.get(f"{base_url}/.well-known/jwks.json", timeout=5)
            break
        except requests.ConnectionError:
            time.sleep(0.1)

    yield httpd
    httpd.shutdown()


BASE_URL = f"http://{HOST_NAME}:{SERVER_PORT}"

def test_encrypt_decrypt_aes():
    """Test that encrypt_aes and decrypt_aes work correctly together"""
    original_key = b"my_secret_key_for_testing"
    encrypted, kid = store_key_in_db(original_key, int(cur_time()) + 3600)
    decrypted = decrypt_aes(encrypted, kid)
    assert decrypted == original_key

def test_register_endpoint():
    """Test /register endpoint creates a new user and returns a password"""
    response = requests.post(f"{BASE_URL}/register", json={"username": "testuser", "email": "testuser@gmail.com"}, timeout=5)
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "password" in data
    assert data["message"] == "User registered successfully"


def test_register_endpoint_missing_username():
    """Test /register endpoint returns 400 if username is missing"""
    response = requests.post(f"{BASE_URL}/register", json={}, timeout=5)
    assert response.status_code == 400


def test_register_endpoint_duplicate_username():
    """Test /register endpoint returns 400 if username already exists"""
    # First registration should succeed
    response1 = requests.post(f"{BASE_URL}/register", json={"username": "duplicateuser", "email": "duplicateuser1@gmail.com"}, timeout=5)
    assert response1.status_code == 200

    # Second registration with same username should fail
    response2 = requests.post(f"{BASE_URL}/register", json={"username": "duplicateuser", "email": "duplicateuser2@gmail.com"}, timeout=5)
    assert response2.status_code == 400

def test_auth_endpoint_valid_token():
    """Test /auth endpoint returns a valid JWT"""
    # Add a user to ensure we have a valid username in the database
    response1 = requests.post(f"{BASE_URL}/register", json={"username": "authuser", "email": "authuser@gmail.com"}, timeout=5)
    assert response1.status_code == 200
    password = response1.json()["password"]
    response2 = requests.post(f"{BASE_URL}/auth", json={"username": "authuser", "password": password}, timeout=5)
    assert response2.status_code == 200

    token = response2.text
    # Verify it's a JWT (has 3 parts separated by dots)
    assert len(token.split('.')) == 3


def test_auth_endpoint_expired_token():
    """Test /auth endpoint with expired parameter"""
    # Add a user to ensure we have a valid username in the database
    response1 = requests.post(f"{BASE_URL}/register", json={"username": "expauthuser", "email": "expauthuser@gmail.com"}, timeout=5)
    assert response1.status_code == 200
    password = response1.json()["password"]
    response = requests.post(f"{BASE_URL}/auth?expired=true", json={"username": "expauthuser", "password": password}, timeout=5)
    assert response.status_code == 200
    token = response.text
    assert len(token.split('.')) == 3

    # Decode without verification to check expiration
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert "exp" in decoded


def test_jwks_endpoint():
    """Test /.well-known/jwks.json endpoint returns proper JWKS"""
    response = requests.get(f"{BASE_URL}/.well-known/jwks.json", timeout=5)
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/json"

    jwks = response.json()
    assert "keys" in jwks
    assert len(jwks["keys"]) > 0

    key = jwks["keys"][0]
    assert key["alg"] == "RS256"
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["kid"] == "goodKID"
    assert "n" in key
    assert "e" in key


def test_auth_method_not_allowed(server):
    """Test that non-POST requests to /auth return 405"""
    response = requests.get(f"{BASE_URL}/auth", timeout=5)
    assert response.status_code == 405


def test_jwks_method_not_allowed(server):
    """Test that non-GET requests to /.well-known/jwks.json return 405"""
    response = requests.post(f"{BASE_URL}/.well-known/jwks.json", timeout=5)
    assert response.status_code == 405


def test_invalid_endpoint(server):
    """Test that invalid endpoints return 405"""
    response = requests.get(f"{BASE_URL}/invalid", timeout=5)
    assert response.status_code == 405


def test_put_method_not_allowed(server):
    """Test PUT method returns 405"""
    response = requests.put(f"{BASE_URL}/auth", timeout=5)
    assert response.status_code == 405


def test_patch_method_not_allowed():
    """Test PATCH method returns 405"""
    response = requests.patch(f"{BASE_URL}/auth", timeout=5)
    assert response.status_code == 405


def test_delete_method_not_allowed():
    """Test DELETE method returns 405"""
    response = requests.delete(f"{BASE_URL}/auth", timeout=5)
    assert response.status_code == 405


def test_head_method_not_allowed():
    """Test HEAD method returns 405"""
    response = requests.head(f"{BASE_URL}/auth", timeout=5)
    assert response.status_code == 405

