import threading
import time
from http.server import HTTPServer
import pytest
import requests
import jwt
from main import MyServer, HOST_NAME, SERVER_PORT


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
            requests.get(f"{base_url}/.well-known/jwks.json")
            break
        except requests.ConnectionError:
            time.sleep(0.1)
            
    yield httpd
    httpd.shutdown()


BASE_URL = f"http://{HOST_NAME}:{SERVER_PORT}"


def test_auth_endpoint_valid_token(server):
    """Test /auth endpoint returns a valid JWT"""
    response = requests.post(f"{BASE_URL}/auth")
    assert response.status_code == 200
    
    token = response.text
    # Verify it's a JWT (has 3 parts separated by dots)
    assert len(token.split('.')) == 3


def test_auth_endpoint_expired_token(server):
    """Test /auth endpoint with expired parameter"""
    response = requests.post(f"{BASE_URL}/auth?expired=true")
    assert response.status_code == 200
    token = response.text
    assert len(token.split('.')) == 3
    
    # Decode without verification to check expiration
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert "exp" in decoded


def test_jwks_endpoint(server):
    """Test /.well-known/jwks.json endpoint returns proper JWKS"""
    response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
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
    response = requests.get(f"{BASE_URL}/auth")
    assert response.status_code == 405


def test_jwks_method_not_allowed(server):
    """Test that non-GET requests to /.well-known/jwks.json return 405"""
    response = requests.post(f"{BASE_URL}/.well-known/jwks.json")
    assert response.status_code == 405


def test_invalid_endpoint(server):
    """Test that invalid endpoints return 405"""
    response = requests.get(f"{BASE_URL}/invalid")
    assert response.status_code == 405


def test_put_method_not_allowed(server):
    """Test PUT method returns 405"""
    response = requests.put(f"{BASE_URL}/auth")
    assert response.status_code == 405


def test_patch_method_not_allowed(server):
    """Test PATCH method returns 405"""
    response = requests.patch(f"{BASE_URL}/auth")
    assert response.status_code == 405


def test_delete_method_not_allowed(server):
    """Test DELETE method returns 405"""
    response = requests.delete(f"{BASE_URL}/auth")
    assert response.status_code == 405


def test_head_method_not_allowed(server):
    """Test HEAD method returns 405"""
    response = requests.head(f"{BASE_URL}/auth")
    assert response.status_code == 405
