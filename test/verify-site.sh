#!/usr/bin/env bash
# Memastikan hardening tidak merusak situs: pengunjung biasa tetap bisa memakai website.
# Usage: ./verify-site.sh [host:port-https]   (default 127.0.0.1:8443)
T=${1:-127.0.0.1:8443}
if [[ -t 1 || -n ${FORCE_COLOR:-} ]]; then R=$'\e[31m' G=$'\e[32m' N=$'\e[0m'; else R='' G='' N=''; fi
ok=0
check() { # check <deskripsi> <url> <teks yang harus ada di halaman>
  local body c
  body=$(curl -sk -m 15 -w '\n%{http_code}' "$2")
  c=${body##*$'\n'}
  if [[ $c == 200 && $body == *"$3"* ]]; then echo "${G}[PASS]${N} $1 (HTTP 200)"
  else echo "${R}[FAIL]${N} $1 (HTTP $c)"; ok=1; fi
}

check "Halaman utama tampil"            "https://$T/"                       "Toko Demo"
check "Halaman artikel terbuka"         "https://$T/promo-akhir-bulan/"     "Diskon"
check "Pencarian biasa tidak salah blokir" "https://$T/?s=promo"            "Toko Demo"
check "Halaman login terbuka"           "https://$T/wp-login.php"           "user_login"
exit $ok
