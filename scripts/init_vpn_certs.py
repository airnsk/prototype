#!/usr/bin/env python3
"""
Генерация сертификатов OpenVPN через cryptography (без easy-rsa).
Создаёт CA, серверный и клиентский сертификаты.
"""

import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_cert(subject_name, issuer_key, issuer_cert, subject_key, serial, days=365, is_ca=False):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZTNA-Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer_cert.subject if issuer_cert else subject)
    builder = builder.public_key(subject_key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=days))
    
    san = x509.SubjectAlternativeName([x509.DNSName(subject_name)])
    builder = builder.add_extension(san, critical=False)
    
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                          content_commitment=False, key_encipherment=False, data_encipherment=False,
                          key_agreement=False, encipher_only=False, decipher_only=False),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, key_encipherment=True,
                          content_commitment=False, data_encipherment=False,
                          key_agreement=False, key_cert_sign=False, crl_sign=False,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH if "server" in subject_name else x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    
    sign_key = issuer_key if issuer_key else subject_key
    cert = builder.sign(sign_key, hashes.SHA256())
    return cert


def save_key(path, key):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))


def save_cert(path, cert):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def main():
    base_dir = os.path.join(os.path.dirname(__file__), "..", "vpn", "certs")
    os.makedirs(base_dir, exist_ok=True)
    
    if os.path.exists(os.path.join(base_dir, "ca.crt")):
        print("[vpn] Certificates already exist.")
        return
    
    # CA
    ca_key = generate_key()
    ca_cert = make_cert("OpenVPN CA", None, None, ca_key, serial=1, days=3650, is_ca=True)
    save_key(os.path.join(base_dir, "ca.key"), ca_key)
    save_cert(os.path.join(base_dir, "ca.crt"), ca_cert)
    
    # Server
    server_key = generate_key()
    server_cert = make_cert("server", ca_key, ca_cert, server_key, serial=2, days=365)
    save_key(os.path.join(base_dir, "server.key"), server_key)
    save_cert(os.path.join(base_dir, "server.crt"), server_cert)
    
    # Client
    client_key = generate_key()
    client_cert = make_cert("client", ca_key, ca_cert, client_key, serial=3, days=365)
    save_key(os.path.join(base_dir, "client.key"), client_key)
    save_cert(os.path.join(base_dir, "client.crt"), client_cert)
    
    # DH params (фиксированные для прототипа)
    # В продакшене нужно генерировать 2048+ бит
    dh_pem = """-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAziCFOi0gvmhhpTgo9BTKp+1C2
//////////+t+FRYortKmq/cViAziCFOi0gvmhhpTgo9BTKp+1C2//////////+t
+FRYortKmq/cViAziCFOi0gvmhhpTgo9BTKp+1C2//////////+t+FRYortKmq/c
ViAziCFOi0gvmhhpTgo9BTKp+1C2//////////+t+FRYortKmq/cViAziCFOi0gv
mhhpTgo9BTKp+1C2//////////+t+FRYortKmq/cViAziCFOi0gvmhhpTgo9BTKp
+1C2AQ//////////pNki+ICrHBq4j5QUlf1G0kX/HajPAZzxpjOe2jZqHnDk1n
3wOwIDAQAB
-----END DH PARAMETERS-----"""
    with open(os.path.join(base_dir, "dh.pem"), "w") as f:
        f.write(dh_pem)
    
    print(f"[vpn] Certificates generated in {base_dir}")


if __name__ == "__main__":
    main()
