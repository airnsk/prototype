FROM alpine:3.19

RUN apk add --no-cache openvpn iptables ip6tables curl

# Создаём директории
RUN mkdir -p /etc/openvpn/certs /etc/openvpn/ccd /var/log/openvpn

COPY vpn/server.conf /etc/openvpn/server.conf
COPY vpn/certs/ /etc/openvpn/certs/
COPY vpn/init.sh /usr/local/bin/init.sh
RUN chmod +x /usr/local/bin/init.sh

# Разрешаем форвардинг
RUN echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

EXPOSE 1194/udp

CMD ["openvpn", "--config", "/etc/openvpn/server.conf"]
