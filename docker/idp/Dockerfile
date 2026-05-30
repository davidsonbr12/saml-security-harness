FROM php:8.3-apache

RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    libxml2-dev \
    curl \
    unzip \
    git \
    && docker-php-ext-install xml bcmath \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /var/simplesamlphp

RUN curl -sS https://getcomposer.org/installer | php -- \
    --install-dir=/usr/local/bin --filename=composer

RUN composer create-project simplesamlphp/simplesamlphp:^2.5 . \
    --no-interaction --no-dev

RUN mkdir -p cert && \
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout cert/idp.key \
        -out cert/idp.crt \
        -days 3650 \
        -subj "/CN=saml-idp" && \
    chown www-data:www-data cert/idp.key cert/idp.crt
COPY config/ /var/simplesamlphp/config/

COPY metadata/ /var/simplesamlphp/metadata/

RUN echo 'Alias /simplesaml /var/simplesamlphp/public\n\
<Directory /var/simplesamlphp/public>\n\
    Require all granted\n\
    AllowOverride All\n\
</Directory>' > /etc/apache2/conf-enabled/simplesamlphp.conf \
    && a2enmod rewrite headers

EXPOSE 80
