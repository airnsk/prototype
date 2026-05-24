#!/bin/sh
# Генерация сертификатов OpenVPN через easy-rsa
set -e

EASYRSA_DIR="/etc/openvpn/easy-rsa"
CERTS_DIR="/etc/openvpn/certs"

# Установка easy-rsa если нет
if ! command -v easyrsa >/dev/null 2>&1; then
    apk add --no-cache easy-rsa
fi

mkdir -p "$CERTS_DIR"

# Инициализация PKI
if [ ! -f "$CERTS_DIR/ca.crt" ]; then
    rm -rf "$EASYRSA_DIR"
    cp -r /usr/share/easy-rsa "$EASYRSA_DIR"
    cd "$EASYRSA_DIR"
    
    ./easyrsa init-pki
    echo "set_var EASYRSA_REQ_CN \"OpenVPN CA\"" > vars
    
    # CA
    ./easyrsa --batch build-ca nopass
    
    # Сервер
    ./easyrsa --batch build-server-full server nopass
    
    # Клиент
    ./easyrsa --batch build-client-full client nopass
    
    # DH
    ./easyrsa gen-dh
    
    # Копируем сертификаты
    cp pki/ca.crt "$CERTS_DIR/"
    cp pki/issued/server.crt "$CERTS_DIR/"
    cp pki/private/server.key "$CERTS_DIR/"
    cp pki/issued/client.crt "$CERTS_DIR/"
    cp pki/private/client.key "$CERTS_DIR/"
    cp pki/dh.pem "$CERTS_DIR/"
    
    echo "[vpn] Certificates generated."
else
    echo "[vpn] Certificates already exist."
fi
