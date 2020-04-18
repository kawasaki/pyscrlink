#!/bin/bash
CERT_FILE=scratch-device-manager.cer
KEY_FILE=scratch-device-manager.key

# Generate certificate and key files
openssl req -x509 -out "${CERT_FILE}" -keyout "${KEY_FILE}" -newkey rsa:2048 \
	-nodes -sha256 -days 3650 -extensions EXT -config /dev/stdin << HERE
[dn]
CN = device-manager.scratch.mit.edu
[req]
prompt = no
distinguished_name = dn
[EXT]
subjectAltName = DNS:device-manager.scratch.mit.edu
HERE

