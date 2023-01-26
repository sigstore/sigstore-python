#/bin/bash

grep -nr "b64\|base64\|cert_pem\|pem" sigstore/* test/* > key_lines.txt
