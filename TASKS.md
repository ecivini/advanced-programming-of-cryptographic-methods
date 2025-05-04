# High level TODO list
- [ ] (Emanuele+Alessia) Draw a diagram of the components and the interactions
- [ ] (Emanuele) Setup HSM for key management
- [ ] (Alessia) Setup a database
- [ ] (Emanuele) Create API to interact with the HSM
- [ ] (Alessia) Create API for certificate management
- [ ] (Emanuele+Alessia) Create UI for the CA
- [ ] (Emanuele+Alessia) Write report

## API Certificate Management 
- [ ] (PUT) Commit email and public key
- [ ] (PUT) Create certificate upon challenge verification
- [ ] (GET) Get root certificate
- [ ] (POST) Revoke certificate
- [ ] (GET) Get Certificate Revocation List
- [ ] (POST) Renew certificate

## API HSM
- [x] Generate root key pair
- [x] Generate root certificate
- [x] Get root public key
- [x] Sign messages
- [ ] Verify signatures
