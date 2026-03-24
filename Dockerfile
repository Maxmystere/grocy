# ── Stage 1: Frontend packages (Node.js / Yarn) ────────────────────────────
FROM node:20-alpine AS frontend-builder

# git is required by Yarn to resolve git-URL dependencies
RUN apk add --no-cache git

WORKDIR /app

# Copy only the dependency manifests first for better layer caching
COPY package.json yarn.lock .yarnrc ./

# Install frontend packages into public/packages (configured via .yarnrc)
RUN yarn install

# ── Stage 2: PHP runtime (Apache) ───────────────────────────────────────────
FROM php:8.5-apache

# Install system libraries needed to compile PHP extensions, plus runtime tools
RUN apt-get update && apt-get install -y --no-install-recommends \
        libicu-dev \
        libgd-dev \
        libjpeg62-turbo-dev \
        libwebp-dev \
        libpng-dev \
        libfreetype6-dev \
        unzip \
        curl \
    && docker-php-ext-configure gd \
        --with-jpeg \
        --with-webp \
        --with-freetype \
    && docker-php-ext-install -j"$(nproc)" gd intl pdo_sqlite \
    && rm -rf /var/lib/apt/lists/*

# Enable Apache mod_rewrite (required by the .htaccess in public/)
RUN a2enmod rewrite

# Replace the default Apache site with a Grocy-aware VirtualHost
COPY docker/apache.conf /etc/apache2/sites-available/000-default.conf

# Pull in the Composer binary from the official Composer image
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

# Copy application source (everything not excluded by .dockerignore)
COPY . .

# Copy the compiled frontend packages from Stage 1
COPY --from=frontend-builder /app/public/packages ./public/packages

# Install PHP dependencies using the locked versions
RUN COMPOSER_ALLOW_SUPERUSER=1 composer install \
        --no-dev \
        --optimize-autoloader \
        --no-interaction

# Bootstrap the data directory: create config.php from the distribution template
# and grant the web server write access (needed for the SQLite DB and view cache)
RUN cp config-dist.php data/config.php \
    && chown -R www-data:www-data data

EXPOSE 80

# Health check: the app redirects on first boot (hash init), subsequent calls are 200
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=5 \
    CMD curl -so /dev/null http://localhost/ || exit 1
