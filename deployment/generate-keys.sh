#!/usr/bin/env bash

# Copyright (c) 2019 StackRox Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# generate-keys.sh
#
# Generate a (self-signed) CA certificate and a certificate and private key to be used by the webhook demo server.
# The certificate will be issued for the Common Name (CN) of `webhook-server.webhook-demo.svc`, which is the
# cluster-internal DNS name for the service.
#
# NOTE: THIS SCRIPT EXISTS FOR DEMO PURPOSES ONLY. DO NOT USE IT FOR YOUR PRODUCTION WORKLOADS.

: "${1?'missing key directory'}"

key_dir="$1"

chmod 0700 "$key_dir"
cd "$key_dir"

cat <<EOF >>san_req_ext.cfg
[ req ]
req_extensions     = san_reqext       # Desired extensions
distinguished_name = req_distinguished_name
prompt             = no

[req_distinguished_name]
commonName = webhook-server.webhook-demo.svc

[ san_reqext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.0 = webhook-server.webhook-demo.svc
DNS.1 = webhook-server.webhook-demo.svc.cluster.local
EOF

# Generate the CA cert and private key
openssl req -nodes -new -x509 -keyout ca.key -out ca.crt -subj "/CN=Admission Controller Webhook Demo CA"
# Generate the private key for the webhook server
openssl genrsa -out webhook-server-tls.key 2048
# Generate a Certificate Signing Request (CSR) for the private key, and sign it with the private key of the CA.
openssl req -new -key webhook-server-tls.key -config san_req_ext.cfg -extensions san_reqext -subj "/CN=webhook-server.webhook-demo.svc" |
    openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial -extfile san_req_ext.cfg -extensions san_reqext -out webhook-server-tls.crt
