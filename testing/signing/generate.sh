#!/usr/bin/env bash
set -euo pipefail

# =========================
# Configuration
# =========================

CERT_NAME="MyTestDriverCert"
SUBJECT="/CN=${CERT_NAME}"
OUT_DIR=${OUT_DIR:-"."}
DAYS=365
PFX_PASSWORD="changeit"

# =========================
# Prepare output directory
# =========================

mkdir -p "${OUT_DIR}"

KEY_FILE="${OUT_DIR}/${CERT_NAME}.key"
CRT_FILE="${OUT_DIR}/${CERT_NAME}.crt"
CER_FILE="${OUT_DIR}/${CERT_NAME}.cer"
PFX_FILE="${OUT_DIR}/${CERT_NAME}.pfx"
EXT_FILE="${OUT_DIR}/${CERT_NAME}.ext"

# =========================
# Create OpenSSL extension file
# =========================
# codeSigning EKU:
#   1.3.6.1.5.5.7.3.3

cat > "${EXT_FILE}" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

# =========================
# Generate private key
# =========================

openssl genrsa -out "${KEY_FILE}" 2048

# =========================
# Generate self-signed certificate
# =========================

openssl req \
  -new \
  -x509 \
  -sha256 \
  -days "${DAYS}" \
  -key "${KEY_FILE}" \
  -out "${CRT_FILE}" \
  -subj "${SUBJECT}" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=codeSigning" \
  -addext "subjectKeyIdentifier=hash"

# =========================
# Export DER .cer for Windows cert store import
# =========================

openssl x509 \
  -in "${CRT_FILE}" \
  -outform DER \
  -out "${CER_FILE}"

# =========================
# Export PFX for Windows SignTool
# =========================

openssl pkcs12 \
  -export \
  -out "${PFX_FILE}" \
  -inkey "${KEY_FILE}" \
  -in "${CRT_FILE}" \
  -name "${CERT_NAME}" \
  -passout "pass:${PFX_PASSWORD}"

echo
echo "Certificate files created:"
echo "  Private key : ${KEY_FILE}"
echo "  PEM cert    : ${CRT_FILE}"
echo "  DER cert    : ${CER_FILE}"
echo "  PFX file    : ${PFX_FILE}"
echo
echo "PFX password:"
echo "  ${PFX_PASSWORD}"
echo
echo "Next steps on Windows:"
echo "  certutil -addstore -f Root ${CERT_NAME}.cer"
echo "  certutil -addstore -f TrustedPublisher ${CERT_NAME}.cer"
echo
echo "Example SignTool command:"
echo "  signtool sign /v /fd SHA256 /f ${CERT_NAME}.pfx /p ${PFX_PASSWORD} MyDriver.cat"