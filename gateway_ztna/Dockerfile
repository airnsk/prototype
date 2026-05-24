FROM nginx:alpine

# Установка apache2-utils для htpasswd
RUN apk add --no-cache apache2-utils

# Удаляем дефолтный конфиг
RUN rm /etc/nginx/conf.d/default.conf

# Копируем конфигурацию
COPY gateway_ztna/nginx.conf /etc/nginx/conf.d/ztna.conf
COPY gateway_ztna/htpasswd /etc/nginx/htpasswd
COPY gateway_ztna/certs/ /etc/nginx/certs/

EXPOSE 8443

CMD ["nginx", "-g", "daemon off;"]
