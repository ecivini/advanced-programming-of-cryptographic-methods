# Advanced Programming of Cryptographic Methods

## Team members
- Emanuele Civini, emanuele.civini@studenti.unitn.it
- Alessia Pivotto, alessia.pivotto@studenti.unitn.it

## Project description
In secure communication systems, a Certificate Authority (CA) is responsible for issuing and managing certificates inside a Public Key Infrastructure (PKI). These certificates authenticate the identities of entities and bind them to their public keys, and form the foundation for secure communications between multiple parties.

This project involves implementing a simplified CA capable of handling operations such as certificate issuance, validation, renewal and revocation. In addition, we are going to use a cloud HSM to securely store the private key of the CA and process the signing requests. 

The CA will also verify that the certificate holders effectively own the correct private key and email.

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

## Report
A report containing documentation, requirements, known limitations and architectural choices can be found [here](./report/ReportAPoCM.pdf).