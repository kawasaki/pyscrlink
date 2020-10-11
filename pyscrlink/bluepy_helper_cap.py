#!/usr/bin/env python

import sys
import os
import shutil
import bluepy
import subprocess

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
    "setcap": "libcap2-bin (Ubuntu) or libcap (Arch)",
}

for cmd in DEPENDENT_TOOLS:
    if not shutil.which(cmd):
        print(f"'{cmd}' not found. Install package {DEPENDENT_TOOLS[cmd]}.")
        sys.exit(1)

def helper_path():
    path = os.path.abspath(bluepy.__file__)
    if not path:
        logger.error("Bluepy module not found")
        sys.exit(1)
    if path.find("__init__.py") < 0:
        logger.error(f"Unexpected bluepy module path: {path}")
        sys.exit(1)
    path = path.replace("__init__.py", "bluepy-helper")
    return path

def is_set():
    path = helper_path()
    p = subprocess.run(["getcap", path], capture_output=True)
    if p.returncode !=0:
        logger.error(f"Failed to get capability of {path}")
        return False
    out = str(p.stdout)
    return out.find("cap_net_admin") >= 0 and out.find("cap_net_raw") >= 0

def setcap():
    path = helper_path()
    if is_set():
        return True
    p = subprocess.run(["sudo", "setcap", "cap_net_raw,cap_net_admin+eip", \
                        path], capture_output=True)
    if p.returncode !=0:
        logger.error(f"Failed to set capability to {path}")
        return False
    print(f"Set capacbility 'cap_net_raw,cap_net_admin' to {path}")
    return True

if __name__ == "__main__":
    setcap()
