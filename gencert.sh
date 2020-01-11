openssl req -x509 -out scratch-device-manager.cer \
-keyout scratch-device-manager.key -newkey rsa:2048 -nodes -sha256 \
-subj '/CN=scratch-device-manager' -extensions EXT -config <( \
printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
grep -h ^ scratch-device-manager.cer scratch-device-manager.key \
  | tr -d '\r' > scratch-device-manager.pem
