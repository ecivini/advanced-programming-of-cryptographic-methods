# Advanced Programming of Cryptographic Methods

## Team members
- Emanuele Civini, emanuele.civini@studenti.unitn.it
- Alessia Pivotto, alessia.pivotto@studenti.unitn.it

## Project description
In secure communication systems, a Certificate Authority (CA) is responsible for issuing and managing certificates inside a Public Key Infrastructure (PKI). These certificates authenticate the identities of entities and bind them to their public keys, and form the foundation for secure communications between multiple parties.

This project involves implementing a simplified CA capable of handling operations such as certificate issuance, validation, renewal and revocation. In addition, we are going to use a cloud HSM to securely store the private key of the CA and process the signing requests. 

The CA will also verify that the certificate holders effectively own the correct private key and email.

## Report
TODO

## Requirements
TODO

## Usage

### Starting the server
In order to start the server, run:
```bash
$ docker compose up --build
```
During the first startup, the server will automatically create a new root keypair in the HSM and create the root certificate for the CA. In order to create a new keypair and certificate, you have to clean the HSM data by running:
```bash
$ docker container rm local-kms
```

## Test: ECDSA

Start by creating a private key, in this case for ECDSA:
```bash
$ openssl ecparam -name prime256v1 -genkey -noout -out priv-key.pem
```
Extract the associated public key:
```bash
$ openssl ec -in priv-key.pem -pubout > pub-key.pem
```
Sign the challenge:
```bash
$ cat challenge.txt | base64 -d > challenge_raw.bin && openssl dgst -sha256 -sign priv-key.pem challenge_raw.bin | base64 > signature.txt && rm challenge_raw.bin 
```

## Test: RSA

Start by creating a private key, in this case for RSA:
```bash
$ openssl genrsa -out priv-key-rsa.pem 4096
```
Extract the associated public key:
```bash
$ openssl rsa -in priv-key-rsa.pem -pubout -out pub-key-rsa.pem
```
Sign the challenge:
```bash
$ cat challenge.txt | base64 -d > challenge_raw.bin && openssl dgst -sha256 -sign priv-key-rsa.pem challenge_raw.bin | base64 > signature.txt && rm challenge_raw.bin 
```