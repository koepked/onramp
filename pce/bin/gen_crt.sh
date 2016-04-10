#!/bin/bash

PCE_KEY_FILE=src/keys/onramp_pce.key
PCE_CERT_FILE=src/keys/onramp_pce.crt
PCE_OPENSSL_CONF=src/openssl.cnf
PCE_CERT_DAYS=365
PCE_PERMISSION=400
PCE_ALG=rsa
PCE_BITS=2048

openssl req \
    -newkey $PCE_ALG:$PCE_BITS \
    -sha256 \
    -keyout $PCE_KEY_FILE \
    -nodes \
    -x509 \
    -config $PCE_OPENSSL_CONF \
    -out $PCE_CERT_FILE \
    -days $PCE_CERT_DAYS

chmod $PCE_PERMISSION $PCE_KEY_FILE
chmod $PCE_PERMISSION $PCE_CERT_FILE
