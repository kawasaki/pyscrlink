#!/bin/bash
openssl req -x509 -out scratch-device-manager.pem \
	-keyout scratch-device-manager.pem -newkey rsa:2048 -nodes -sha256 \
	-days 3650 -extensions EXT -config /dev/stdin << HERE
[dn]
CN = device-manager.scratch.mit.edu
[req]
prompt = no
distinguished_name = dn
[EXT]
subjectAltName = DNS:device-manager.scratch.mit.edu
HERE
