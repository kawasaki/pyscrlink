#!/usr/bin/env python

import subprocess
import shutil
import sys
import os
import re
from OpenSSL import crypto

import logging
logLevel = logging.INFO

# for logging
logger = logging.getLogger(__name__)
formatter = logging.Formatter(fmt='%(asctime)s %(message)s')
handler = logging.StreamHandler()
handler.setLevel(logLevel)
handler.setFormatter(formatter)
logger.setLevel(logLevel)
logger.addHandler(handler)
logger.propagate = False

# Check dependent tools
DEPENDENT_TOOLS = {
    "certutil": "libnss3-tools (Ubuntu) or nss (Arch)",
}

for cmd in DEPENDENT_TOOLS:
    if not shutil.which(cmd):
        print(f"'{cmd}' not found. Install package {DEPENDENT_TOOLS[cmd]}.")
        sys.exit(1)

# The python-nss package 1.0.1 does not provide API to delete certificates to
# NSSDB. Instead, utilize certutil command.

SCRATCH_CERT_NICKNAME = "device-manager.scratch.mit.edu"

homedir = os.path.expanduser('~')
localdir = os.path.join(homedir, ".local/share/pyscrlink/")
cert_file_path = os.path.join(localdir, "scratch-device-manager.cer")
key_file_path = os.path.join(localdir, "scratch-device-manager.key")

def gen_cert(cert_path, key_path):
    """
    Generate certificate and key for scratch-link
    """
    os.makedirs(localdir, exist_ok=True)

    if os.path.isfile(cert_path) and os.path.isfile(key_path):
        if is_cert_valid(cert_path):
            logger.debug(f"Alreadfy {cert_path} and {key_path} are genereated.")
            return
        else:
            logger.info(f"Certificate {cert_path} expired. Regenerate it.")

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = SCRATCH_CERT_NICKNAME
    cert.gmtime_adj_notBefore(9)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)  # ten years
    cert.set_pubkey(key)
    cert.set_issuer(cert.get_subject())
    cert.add_extensions([
        crypto.X509Extension(b"subjectAltName", False,
                             b"DNS:device-manager.scratch.mit.edu")
    ])
    cert.sign(key, 'sha256')

    with open(cert_path, "wb") as cf:
        cf.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_path, "wb") as kf:
        kf.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    logger.info(f"Generated certificate: {cert_path}")
    logger.info(f"Generated key: {key_path}")

def certutil_db_name(dir):
    prefix = "dbm" if os.path.isfile(os.path.join(dir, "key3.db")) else "sql"
    return prefix + ":" + dir

def remove_cert(dir, nickname):
    while True:
        p = subprocess.run(["certutil", "-L", "-d", certutil_db_name(dir),
                            "-n", nickname], capture_output=True)
        if p.returncode != 0:
            break
        logger.info(f"Delete certificate {nickname} from {dir}")
        p = subprocess.run(["certutil", "-D", "-d", certutil_db_name(dir),
                            "-n", nickname])

def is_cert_valid(cert_path):
    """
    Check if the certificate at specified path is valid
    """
    with open(cert_path, "rb") as cf:
        cbarr = cf.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cbarr)
    return not cert.has_expired()

def has_cert(dir, cert, nickname):
    """
    Check if given NSSDB at dir has the certificate with the nickname.
    """
    # Try to list with given nick name.
    p = subprocess.run(["certutil", "-L", "-d", certutil_db_name(dir),
                        "-n", nickname], capture_output=True)
    if p.returncode != 0:
        # No certificate with the nick name.
        return False

    # Get the certificate in the NSSDB.
    p = subprocess.run(["certutil", "-L", "-d", certutil_db_name(dir),
                            "-n", nickname, "-a"], capture_output=True)
    assert (p.returncode == 0), "Unexpected certutil result"
    cert_in_db = p.stdout.replace(b'\r\n', b'\n')

    # Get the certificate in the specified cert file.
    with open(cert, 'rb') as f:
        file_barr = f.read()
    cert_in_file = file_barr.replace(b'\r\n', b'\n')

    # Compare the two certificates.
    for i in range(len(cert_in_db)):
        if cert_in_db[i] != cert_in_file[i]:
            logger.info(f"Old certificate is in {dir}.")
            return False
    logger.debug(f"NSSDB at {dir} has valid certificate.")
    return True

def add_cert(dir, cert, nickname):
    """
    Add certification to the NSS db in the specified directory.
    """
    p = subprocess.run(["certutil", "-A", "-d", certutil_db_name(dir),
                        "-n", nickname,
                        "-t", "C,,", "-i", cert])
    return p.returncode

def prep_nss_cert(dir, cert, nickname):
    """
    Prepare specified certificate with specified nickname in the NSSDB at
    specified directory.
    """
    if has_cert(dir, cert, nickname):
        return
    logger.info(f"Add the new certificate to {dir}")
    remove_cert(dir, nickname)
    add_cert(dir, cert, nickname)

def prep_cert():
    # Generate certification and key
    gen_cert(cert_file_path, key_file_path)

    # Add certificate to FireFox
    nssdb = None
    firefox_nss_path = os.path.join(homedir, ".mozilla/firefox/")
    for root, dirs, files in os.walk(firefox_nss_path):
        for name in files:
            if not re.match("key.*\.db", name):
                continue
            nssdb = root
            if prep_nss_cert(nssdb, cert_file_path, SCRATCH_CERT_NICKNAME):
                logger.error(f"Failed to add certificate to FireFox NSS DB: {nssdb}")
                sys.exit(3)
            else:
                logger.info(f"Certificate is ready in FireFox NSS DB: {nssdb}")
    if not nssdb:
        logger.info("FireFox NSS DB not found. Do not add certificate.")

    # Add certificate to Chrome
    nssdb = os.path.join(homedir, ".pki/nssdb")
    if os.path.isdir(nssdb):
        if prep_nss_cert(nssdb, cert_file_path, SCRATCH_CERT_NICKNAME):
            logger.error(f"Failed to add certificate to Chrome")
            sys.exit(4)
        else:
            logger.info("Certificate is ready for Chrome")
    else:
        logger.info("Chrome NSS DB not found. Do not add certificate.")

if __name__ == "__main__":
    prep_cert()
