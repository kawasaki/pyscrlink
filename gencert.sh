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

if ((!$?)); then
	echo "Generated certificate: ${CERT_FILE}"
	echo "Generated key: ${KEY_FILE}"
else
	echo "Failed to generate certificate and key files."
	exit 1
fi

if ! command -v certutil > /dev/null; then
	echo "Certutil command not found. Do not add certificate."
	exit 2
fi

add_cert() {
	local dir="${1}"
	local prefix=sql

	if [[ -e ${dir}/key3.db ]]; then
		prefix=dbm
	fi

	certutil -A -d "${prefix}:${1}" -n "device-manager.scratch.mit.edu" \
		 -t "C,," -i "${CERT_FILE}"
}

# Add certificate to FireFox
declare nssdb
for f in "${HOME}"/.mozilla/firefox/*/key*.db; do
	if [[ ! -f ${f} ]]; then
		continue
	fi
	nssdb=${f%/*}
	if add_cert "${nssdb}"; then
		echo "Added certificate to FireFox NSS DB: ${nssdb}"
	else
		echo "Failed to add certificate to FireFox NSS DB: ${nssdb}"
		exit 3
	fi
done
if [[ -z ${nssdb} ]]; then
	echo "FireFox NSS DB not found. Do not add certificate."
fi

# Add certificate to Chrome
nssdb="${HOME}/.pki/nssdb"
if [[ -d ${nssdb} ]]; then
	if add_cert "${nssdb}"; then
		echo "Added certificate to Chrome"
	else
		echo "Failed to add certificate to Chrome"
		exit 4
	fi
else
	echo "Chrome NSS DB not found. Do not add certificate."
fi
