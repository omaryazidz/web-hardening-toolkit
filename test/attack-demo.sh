#!/usr/bin/env bash
# Simulasi serangan umum terhadap website target, dijalankan dari LUAR server.
# Dipakai sebelum dan sesudah hardening untuk membandingkan apa yang bisa dilakukan penyerang.
# Usage: ./attack-demo.sh [host:port-https]   (default 127.0.0.1:8443)
T=${1:-127.0.0.1:8443}
if [[ -t 1 || -n ${FORCE_COLOR:-} ]]; then R=$'\e[31m' G=$'\e[32m' N=$'\e[0m'; else R='' G='' N=''; fi
code() { curl -sk -o /dev/null -m 10 -w '%{http_code}' "$@"; }
bad() { echo "  ${R}[TERBUKA]${N} $*"; }
good() { echo "  ${G}[AMAN]${N}    $*"; }

echo "Target: https://$T"

echo "1. Header server"
srv=$(curl -skI -m 10 "https://$T/" | grep -i '^server:' | tr -d '\r')
if [[ $srv =~ [0-9]+\.[0-9]+ ]]; then bad "$srv (penyerang tahu versi persisnya)"; else good "${srv:-versi tidak ditampilkan}"; fi

echo "2. Mengunduh file rahasia"
body=$(curl -sk -m 10 "https://$T/.env")
if [[ $body == *DB_PASSWORD* ]]; then bad ".env terunduh -> $(grep DB_PASSWORD <<<"$body")"; else good ".env -> HTTP $(code "https://$T/.env")"; fi
body=$(curl -sk -m 10 "https://$T/.git/config")
if [[ $body == *remote* ]]; then bad ".git/config terunduh -> $(grep url <<<"$body" | tr -d '\t')"; else good ".git/config -> HTTP $(code "https://$T/.git/config")"; fi
body=$(curl -sk -m 10 "https://$T/backup.sql")
if [[ $body == *INSERT* ]]; then bad "backup.sql terunduh (dump database)"; else good "backup.sql -> HTTP $(code "https://$T/backup.sql")"; fi

echo "3. Folder uploads"
if [[ $(curl -sk -m 10 "https://$T/wp-content/uploads/") == *"Index of"* ]]; then bad "isi folder uploads bisa dilihat siapa saja"; else good "directory listing mati"; fi
if [[ $(curl -sk -m 10 "https://$T/wp-content/uploads/test.php") == *"PHP berjalan"* ]]; then bad "file PHP di uploads dieksekusi (celah web shell)"; else good "PHP di uploads tidak dieksekusi"; fi

echo "4. Mengintip username admin"
loc=$(curl -sk -m 10 -o /dev/null -w '%{redirect_url}' "https://$T/?author=1")
if [[ $loc == *"/author/"* ]]; then bad "?author=1 -> ${loc##*/author/}  (username bocor)"; else good "?author=1 -> HTTP $(code "https://$T/?author=1")"; fi
if [[ $(curl -sk -m 10 "https://$T/wp-json/wp/v2/users") == *'"slug"'* ]]; then bad "REST API membuka daftar user"; else good "REST API user -> HTTP $(code "https://$T/wp-json/wp/v2/users")"; fi

echo "5. Payload serangan aplikasi"
c=$(code -G --data-urlencode "id=1' OR '1'='1" "https://$T/")
if [[ $c == 403 ]]; then good "SQL injection -> HTTP 403 (diblokir WAF)"; else bad "SQL injection -> HTTP $c (sampai ke aplikasi)"; fi
c=$(code -G --data-urlencode "s=<script>alert(1)</script>" "https://$T/")
if [[ $c == 403 ]]; then good "XSS -> HTTP 403 (diblokir WAF)"; else bad "XSS -> HTTP $c (sampai ke aplikasi)"; fi

echo "6. Brute force login (20 percobaan password)"
declare -A n
for _ in $(seq 20); do c=$(code -X POST -d 'log=editor1&pwd=salah' "https://$T/wp-login.php"); n[$c]=$((${n[$c]:-0} + 1)); done
summary=$(for k in "${!n[@]}"; do echo -n "HTTP $k x${n[$k]}  "; done)
if [[ -n ${n[429]:-} || -n ${n[503]:-} ]]; then good "$summary (dibatasi rate limit)"; else bad "$summary (semua dilayani, bebas ditebak)"; fi

echo "7. Protokol TLS usang"
legacy=""
for p in tls1 tls1_1; do
  out=$(openssl s_client -connect "$T" "-$p" -cipher 'DEFAULT:@SECLEVEL=0' </dev/null 2>&1)
  [[ $out == *"BEGIN CERTIFICATE"* ]] && legacy+="$p "
done
if [[ -n $legacy ]]; then bad "server masih menerima: $legacy"; else good "TLS 1.0/1.1 ditolak"; fi
