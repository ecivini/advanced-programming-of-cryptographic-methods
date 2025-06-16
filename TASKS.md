# High level TODO list
- [x] (Emanuele+Alessia) Draw a diagram of the components and the interactions
- [x] (Emanuele) Setup HSM for key management
- [x] (Alessia) Setup a database
- [x] (Emanuele) Create API to interact with the HSM
- [x] (Alessia) Create API for certificate management
- [x] (Emanuele+Alessia) Create UI for the CA
- [ ] (Emanuele+Alessia) Write report

## API Certificate Management 
- [x] (PUT) Commit email and public key
- [x] (PUT) Create certificate upon challenge verification
- [x] (GET) Get root certificate
- [x] (POST) Revoke certificate
- [x] (GET) Get Certificate Revocation List
- [ ] (POST) Renew certificate

## API HSM
- [x] Generate root key pair
- [x] Generate root certificate
- [x] Get root public key
- [x] Sign messages
- [x] Verify signatures

## Additional checks
- [ ] Flag verified challenged as already used. Certificate creation should fail