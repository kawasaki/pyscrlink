#!/bin/sh
echo "Set up bluepy-helper capability to allow use by normal users"
find /usr -name bluepy-helper -exec sudo setcap \
     'cap_net_raw,cap_net_admin+eip' {} \; 2> /dev/null
find /usr -name bluepy-helper -exec sudo getcap {} \; 2> /dev/null

