#!/usr/bin/env bash
# Membuat WordPress + Nginx dengan kesalahan konfigurasi yang umum ditemukan di server klien.
# HANYA untuk VM lab. Semua rahasia di dalamnya palsu.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1
[[ $EUID -eq 0 ]] || { echo "Jalankan sebagai root."; exit 1; }

WEBROOT=/var/www/html
CERT_DIR=/etc/ssl/lab
DB_PASS=$(openssl rand -hex 12)

apt-get update -qq
apt-get install -y -qq nginx php-fpm php-mysql php-curl php-xml php-mbstring php-gd php-zip \
  mariadb-server curl openssl >/dev/null

# --- WordPress (checksum diverifikasi) ---
cd /tmp
curl -fsSLO https://wordpress.org/latest.tar.gz
echo "$(curl -fsSL https://wordpress.org/latest.tar.gz.sha1)  latest.tar.gz" | sha1sum -c --quiet
rm -rf "${WEBROOT:?}"/* && tar -xzf latest.tar.gz --strip-components=1 -C "$WEBROOT"
curl -fsSL -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x /usr/local/bin/wp
chown -R www-data:www-data "$WEBROOT"
WP=(sudo -u www-data wp --path="$WEBROOT")

mysql -e "CREATE DATABASE IF NOT EXISTS wp; CREATE USER IF NOT EXISTS 'wp'@'localhost' IDENTIFIED BY '$DB_PASS'; GRANT ALL ON wp.* TO 'wp'@'localhost';"
"${WP[@]}" config create --dbname=wp --dbuser=wp --dbpass="$DB_PASS" --skip-check
# host diambil dari request, supaya situs terbuka lewat IP/port apa pun di lab
"${WP[@]}" config set WP_HOME "'https://' . \$_SERVER['HTTP_HOST']" --raw --type=constant
"${WP[@]}" config set WP_SITEURL "'https://' . \$_SERVER['HTTP_HOST']" --raw --type=constant
"${WP[@]}" core install --url=https://lab.test --title="Toko Demo" --admin_user=editor1 \
  --admin_password="$(openssl rand -hex 10)" --admin_email=demo@example.com --skip-email >/dev/null

# situs sungguhan punya artikel (username penulis baru terlihat kalau ada artikel terbit) dan permalink cantik
"${WP[@]}" rewrite structure '/%postname%/' >/dev/null
"${WP[@]}" post create --post_title="Promo Akhir Bulan" --post_content="Diskon semua produk." \
  --post_status=publish --post_author=1 >/dev/null

# --- Kesalahan umum: file sensitif tertinggal di webroot (isi palsu) ---
cat >"$WEBROOT/.env" <<'EOF'
APP_ENV=production
DB_PASSWORD=FAKE-not-a-real-password
STRIPE_SECRET=sk_live_FAKE_0000000000
EOF
mkdir -p "$WEBROOT/.git" "$WEBROOT/wp-content/uploads"
printf '[remote "origin"]\n\turl = https://git.example.com/fake/toko-demo.git\n' >"$WEBROOT/.git/config"
echo "-- FAKE dump: INSERT INTO users VALUES (1,'admin','FAKE-hash');" >"$WEBROOT/backup.sql"
echo '<?php echo "PHP berjalan di folder uploads";' >"$WEBROOT/wp-content/uploads/test.php"
chown -R www-data:www-data "$WEBROOT"

# --- Kesalahan umum: versi PHP terlihat ---
sed -i 's/^expose_php.*/expose_php = On/' /etc/php/*/fpm/php.ini
systemctl restart php*-fpm

# --- TLS: sertifikat self-signed, protokol lama masih diterima ---
mkdir -p "$CERT_DIR"
openssl req -x509 -nodes -newkey rsa:2048 -days 365 -subj "/CN=lab.test" \
  -keyout "$CERT_DIR/web.key" -out "$CERT_DIR/web.crt" 2>/dev/null
chmod 600 "$CERT_DIR/web.key"

PHP_SOCK=$(ls /run/php/php*-fpm.sock | head -1)
rm -f /etc/nginx/sites-enabled/default
cat >/etc/nginx/sites-available/wordpress <<EOF
# Konfigurasi "apa adanya" yang sering ditemukan di server klien
server {
    listen 80;
    listen 443 ssl;
    server_name _;
    root $WEBROOT;
    index index.php;

    ssl_certificate     $CERT_DIR/web.crt;
    ssl_certificate_key $CERT_DIR/web.key;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers 'ALL:@SECLEVEL=0';

    autoindex on;

    location / { try_files \$uri \$uri/ /index.php?\$args; }
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:$PHP_SOCK;
    }
}
EOF
ln -sf /etc/nginx/sites-available/wordpress /etc/nginx/sites-enabled/wordpress
sed -i 's/^\s*server_tokens off;/# server_tokens off;/' /etc/nginx/nginx.conf
nginx -t 2>/dev/null && systemctl restart nginx
echo "setup-ok"
