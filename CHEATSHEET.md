## Test challenge: ECDSA

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

## Test challenge: RSA

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

## Test revokation: ECDSA

Sign the revokation challenge:
```bash
$  openssl dgst -sha256 -sign priv-key.pem revokation.txt | base64 > signature.txt
```

## Test renewal: RSA

Sign the renewal challenge:
```bash
$  openssl dgst -sha256 -sign priv-key-rsa.pem renew.txt | base64 > signature.txt
```