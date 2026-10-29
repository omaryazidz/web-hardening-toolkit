#!/usr/bin/env bash
# Web server hardening: Nginx + WordPress (PHP-FPM), lengkap dengan WAF ModSecurity + OWASP CRS.
# Cocok untuk Ubuntu/Debian. Cek dilakukan lewat HTTP/TLS sungguhan, bukan hanya membaca config.
#
#   sudo ./harden-web.sh audit    # cek saja, tidak mengubah konfigurasi
#   sudo ./harden-web.sh apply    # perbaiki yang FAIL (nginx -t dulu, rollback kalau gagal)
#
# Opsional: HOST (default 127.0.0.1), SITE_CONF (default /etc/nginx/sites-available/wordpress)
# Webroot, sertifikat TLS, dan socket PHP dibaca dari konfigurasi Nginx yang sedang berjalan.
set -uo pipefail

MODE="${1:-audit}"
HOST="${HOST:-127.0.0.1}"
SITE_CONF="${SITE_CONF:-/etc/nginx/sites-available/wordpress}"
HARDEN_CONF=/etc/nginx/conf.d/00-hardening.conf
MODSEC_DIR=/etc/nginx/modsec
BACKUP_DIR="/var/backups/web-hardening-$(date +%Y%m%d-%H%M%S)"

if [[ -t 1 || -n ${FORCE_COLOR:-} ]]; then G=$'\e[32m' R=$'\e[31m' Y=$'\e[33m' N=$'\e[0m'; else G='' R='' Y='' N=''; fi
warn() { echo "  ${Y}[WARN]${N} $*"; }

[[ $EUID -eq 0 ]] || { echo "Jalankan sebagai root (sudo)."; exit 1; }
case "$MODE" in audit|apply) ;; *) echo "Usage: $0 audit|apply"; exit 1 ;; esac
command -v nginx >/dev/null || { echo "Nginx tidak ditemukan."; exit 1; }

NGINX_CFG=$(nginx -T 2>/dev/null)
cfg_val() { awk -v k="$1" '$1==k {gsub(";","",$2); print $2; exit}' <<<"$NGINX_CFG"; }
ROOT=$(cfg_val root)
CERT=$(cfg_val ssl_certificate)
KEY=$(cfg_val ssl_certificate_key)
PHP_SOCK=$(ls /run/php/php*-fpm.sock 2>/dev/null | head -1)

code() { curl -sk -o /dev/null -m 10 -w '%{http_code}' "$@"; }
denied() { [[ $1 == 403 || $1 == 404 ]]; }

# ---------- Pemeriksaan ----------
audit_version_hidden() {
  ! grep -qiE '^server: *nginx/[0-9]' <<<"$(curl -skI -m 10 "https://$HOST/")"
}
audit_sec_headers() {
  local h n
  h=$(curl -skI -m 10 "https://$HOST/")
  for n in strict-transport-security x-content-type-options x-frame-options \
    referrer-policy content-security-policy permissions-policy; do
    grep -qi "^$n:" <<<"$h" || return 1
  done
}
audit_tls_legacy() { # lulus kalau TLS 1.0 dan 1.1 ditolak
  local p out
  for p in tls1 tls1_1; do
    out=$(openssl s_client -connect "$HOST:443" "-$p" -cipher 'DEFAULT:@SECLEVEL=0' </dev/null 2>&1)
    [[ $out == *"BEGIN CERTIFICATE"* ]] && return 1
  done
  return 0
}
audit_sensitive_files() {
  local p
  for p in /.env /.git/config /backup.sql; do denied "$(code "https://$HOST$p")" || return 1; done
}
audit_dir_listing() {
  [[ $(curl -sk -m 10 "https://$HOST/wp-content/uploads/") != *"Index of"* ]]
}
audit_xmlrpc() { denied "$(code -X POST "https://$HOST/xmlrpc.php")"; }
audit_user_enum() {
  [[ $(code "https://$HOST/?author=1") == 403 && $(code "https://$HOST/wp-json/wp/v2/users") == 403 ]]
}
audit_login_ratelimit() { # 12 percobaan login beruntun, harus ada yang ditolak (429/503)
  local c
  for _ in $(seq 12); do
    c=$(code -X POST -d 'log=audit&pwd=audit' "https://$HOST/wp-login.php")
    [[ $c == 429 || $c == 503 ]] && return 0
  done
  return 1
}
audit_waf() {
  [[ $(code -G --data-urlencode "id=1' OR '1'='1" "https://$HOST/") == 403 &&
     $(code -G --data-urlencode "s=<script>alert(1)</script>" "https://$HOST/") == 403 ]]
}
audit_uploads_php() { # PHP di folder uploads tidak boleh dieksekusi (pintu masuk web shell)
  local dir="$ROOT/wp-content/uploads" probe=zz-audit-probe.php c tmp=0
  [[ -d $dir ]] || return 2
  [[ -f $dir/test.php ]] && probe=test.php || { echo '<?php echo 1;' >"$dir/$probe"; tmp=1; }
  c=$(code "https://$HOST/wp-content/uploads/$probe")
  [[ $tmp == 1 ]] && rm -f "$dir/$probe"
  denied "$c"
}
audit_http_redirect() { [[ $(code "http://$HOST/") == 301 ]]; }

# ---------- Perbaikan ----------
backup_once() {
  [[ -d $BACKUP_DIR ]] && return
  mkdir -p "$BACKUP_DIR" && cp -a /etc/nginx "$BACKUP_DIR/nginx"
}

fix_waf() {
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get install -y -qq \
    libnginx-mod-http-modsecurity modsecurity-crs >/dev/null || return 1
  mkdir -p "$MODSEC_DIR"
  cp /etc/nginx/modsecurity.conf /etc/nginx/unicode.mapping "$MODSEC_DIR/"
  sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' "$MODSEC_DIR/modsecurity.conf" # bawaan: DetectionOnly (tidak memblokir)
  cat >"$MODSEC_DIR/main.conf" <<EOF
# Managed by harden-web.sh
Include $MODSEC_DIR/modsecurity.conf
Include /etc/modsecurity/crs/crs-setup.conf
# pengecualian bawaan CRS supaya wp-admin tidak terblokir salah (false positive)
SecAction "id:900130,phase:1,nolog,pass,t:none,setvar:tx.crs_exclusions_wordpress=1"
Include /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
Include /usr/share/modsecurity-crs/rules/*.conf
Include /etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
EOF
}

fix_site() {
  local waf=""
  [[ -f $MODSEC_DIR/main.conf ]] && waf="modsecurity on;
    modsecurity_rules_file $MODSEC_DIR/main.conf;"
  [[ -n $ROOT && -n $CERT && -n $KEY && -n $PHP_SOCK ]] || { warn "webroot/sertifikat/socket PHP tidak terdeteksi"; return 1; }

  cat >"$HARDEN_CONF" <<'EOF'
# Managed by harden-web.sh
limit_req_zone $binary_remote_addr zone=wplogin:10m rate=10r/m;
# 0 = sudah login (boleh akses REST API user), 1 = anonim
map $http_cookie $wp_anon { default 1; "~*wordpress_logged_in_" 0; }
EOF

  cat >"$SITE_CONF" <<EOF
# Managed by harden-web.sh (versi sebelumnya ada di $BACKUP_DIR)
server {
    listen 80;
    server_name _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name _;
    root $ROOT;
    index index.php;
    server_tokens off;
    autoindex off;
    client_max_body_size 20m;
    client_header_timeout 15s;
    client_body_timeout 15s;
    send_timeout 15s;
    $waf

    ssl_certificate     $CERT;
    ssl_certificate_key $KEY;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    # CSP ketat (script-src) mudah merusak tema/plugin WordPress, jadi dipakai versi yang aman
    add_header Content-Security-Policy "frame-ancestors 'self'; base-uri 'self'; object-src 'none'" always;

    if (\$args ~* "(^|&)author=[0-9]") { return 403; }
    if (\$args ~* "rest_route=/wp/v2/users") { return 403; }

    location ~ /\.(?!well-known) { deny all; }
    location ~* \.(sql|bak|old|orig|swp|env|log|ini)\$ { deny all; }
    location = /xmlrpc.php { deny all; }
    location ~* ^/wp-content/(uploads|files)/.*\.php\$ { deny all; }

    location = /wp-login.php {
        limit_req zone=wplogin burst=5 nodelay;
        limit_req_status 429;
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:$PHP_SOCK;
    }
    location ~* ^/wp-json/wp/v2/users {
        if (\$wp_anon) { return 403; }
        try_files \$uri /index.php?\$args;
    }

    location / { try_files \$uri \$uri/ /index.php?\$args; }
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:$PHP_SOCK;
    }
}
EOF
  ln -sf "$SITE_CONF" "/etc/nginx/sites-enabled/$(basename "$SITE_CONF")"
}

# ---------- Runner ----------
CHECKS=(version_hidden sec_headers tls_legacy sensitive_files dir_listing xmlrpc user_enum
  login_ratelimit waf uploads_php http_redirect)
declare -A DESC=(
  [version_hidden]="Versi Nginx tidak terlihat di header Server"
  [sec_headers]="Security header lengkap (HSTS, CSP, X-Frame, dll)"
  [tls_legacy]="TLS 1.0 & 1.1 ditolak (hanya TLS 1.2/1.3)"
  [sensitive_files]=".env, .git, backup.sql tidak bisa diunduh"
  [dir_listing]="Directory listing dimatikan"
  [xmlrpc]="xmlrpc.php diblokir (jalur brute force WordPress)"
  [user_enum]="Daftar username WordPress tidak bocor"
  [login_ratelimit]="Rate limit di halaman login (anti brute force)"
  [waf]="WAF (ModSecurity + OWASP CRS) memblokir SQLi & XSS"
  [uploads_php]="PHP tidak bisa dijalankan dari folder uploads"
  [http_redirect]="HTTP dialihkan ke HTTPS"
)

run_audit() {
  local c rc pass=0 total=0
  echo "== Audit web $(hostname) (nginx $(nginx -v 2>&1 | cut -d/ -f2)) - $(date '+%d %b %Y %H:%M:%S %Z') =="
  for c in "${CHECKS[@]}"; do
    "audit_$c"; rc=$?
    case $rc in
      0) echo "  ${G}[PASS]${N} ${DESC[$c]}"; pass=$((pass + 1)); total=$((total + 1)) ;;
      2) echo "  ${Y}[SKIP]${N} ${DESC[$c]} (tidak berlaku)" ;;
      *) echo "  ${R}[FAIL]${N} ${DESC[$c]}"; total=$((total + 1)) ;;
    esac
  done
  echo "== Skor: $pass/$total =="
}

run_apply() {
  local c rc need_waf=0 need_any=0
  for c in "${CHECKS[@]}"; do
    "audit_$c"; rc=$?
    [[ $rc -eq 0 || $rc -eq 2 ]] && continue
    echo "  [FIX ] ${DESC[$c]}"
    need_any=1
    [[ $c == waf ]] && need_waf=1
  done
  if ((need_any)); then
    backup_once
    ((need_waf)) && { fix_waf || warn "pemasangan WAF gagal"; }
    fix_site
    if nginx -t 2>/dev/null; then
      systemctl restart nginx
    else
      warn "nginx -t gagal, rollback ke backup"
      nginx -t 2>&1 | tail -3
      rm -rf /etc/nginx && cp -a "$BACKUP_DIR/nginx" /etc/nginx && systemctl restart nginx
    fi
    echo "Backup config lama: $BACKUP_DIR"
  fi
  echo
  run_audit
}

"run_$MODE"
