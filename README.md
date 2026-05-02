# Cybersecurity Project - JWKS Server - CSCE 3550-001

Author: Elisabeth Nguyen (Base files for Project 1 by Dr. Hochstetler)

eUID: ehn0018

Last Updated: 5/2/2026

## Project 3 - Bulking up our JWKS server

### Project Overview

The purpose of Project 3 is to bulk up the security of the JWKS server by adding encrypting the private keys before storing them in the database, adding a user login database with the hashed password, logging authentication requests, and adding a rate limiter to the auth endpoint.

### Execution Instructions
(Make sure the totally_not_my_privateKeys.db file is deleted before running test_main.py or the gradebot)

For running with test_main.py testcases:
1. install dependencies with pip (or chosen package manager) - "pip install -r requirements.txt"
2. Set NOT_MY_KEY environment variable to a 32 byte string - e.g. "export NOT_MY_KEY="1nNiBs4u82Jt2GkRc6wBbgwMdKri1Idt" "
3. run server using py or python command - "py main.py" or "python main.py"
4. run test suite with pytest - "pytest test_main.py"

For running with gradebot:

1. execute gradebot (Windows) - "./gradebot.exe project-3 --run="py main.py""
   (replace "py" with "python" based on your setup)

### Project Description

The JWKS server in main.py generates a private key and an expired key for testing purposes when the program is started. The generated keys are then encrypted with AES-CTR encryption and stored with their nonces in the "totally_not_my_private_keys.db" database. Then the program waits for http requests, listening on port 8080. The POST /register endpoint takes in a username and email and generates a UUIDv4 password to return back to the user. It then hashes the password with Argon2 and stores the username, email, and password in the Users table in the database. The POST /auth endpoint first verifies the username and password of the client, logs the authentication request, and then fetches and decrypts a private key from the database and use it to sign a JSON Web Token, which is then encoded and sent to the client server. If the "expired" query parameter is present on the POST /auth request, then the program retrieves and decrypts the expired private key from the database and set the "exp" header in the token to an expiration time of an hour ago. The POST /auth endpoint is also rate-limited at 10 requests per second, so if the limit is reached, the server will return a 429 (Too Many Requests) status code. The /.well-known/jwks.json endpoint fetches all of the valid, unexpired keys from the database and formats the key data into a JSON Web Key Set which is then returned to the client. All other requests, e.g. PUT, PATCH, DELETE, return 405 error codes.

### Code Coverage
The code coverage of the test suite was obtained by running the JWKS server using the "coverage run main.py" command to start tracking the coverage of the server. Then in another terminal, the test suite was run using the "pytest test_main.py" command. Then the JWKS server is closed and the coverage report is displayed using the "coverage report -m" command. As seen in the photo below, the coverage of the test suite is 90%, and all of the test cases passed.
<img width="1280" height="655" alt="image" src="https://github.com/user-attachments/assets/33bf56e3-a98b-48af-bba6-106ef37c39ab" />



### Blackbox testing (gradebot.exe)
For the blackbox testing, the gradebot.exe test client, found [here]([https://github.com/jh125486/CSCE3550/releases]), is moved into the project folder and is executed using the "./gradebot.exe project-3 --run="py main.py"" command.
<img width="1288" height="679" alt="Screenshot 2026-05-02 174507" src="https://github.com/user-attachments/assets/e3abf03c-1723-413d-861f-73411171ccf3" />


