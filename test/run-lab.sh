#!/usr/bin/env bash
# Uji lengkap: boot VM -> pasang WordPress rentan -> serang & audit -> hardening -> serang & audit lagi.
# Layar tetap berwarna (untuk direkam), salinan polos disimpan ke results/.
# Jalankan di lab WSL:  sudo bash test/run-lab.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
mkdir -p results
KEY=/root/weblab/lab_key
SSHO=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
SSH=(ssh -tt -q "${SSHO[@]}" -p 2223 sysadmin@127.0.0.1)
save() { tee >(sed 's/\x1b\[[0-9;]*m//g; s/\r$//' >"results/$1"); }
step() { echo; echo "##### $* #####"; }

if [[ ${1:-} != --no-setup ]]; then
  step "0. MENYIAPKAN SERVER TARGET (WordPress + Nginx bawaan, belum diamankan)"
  bash test/lab-vm.sh down
  bash test/lab-vm.sh up || exit 1
  scp -q "${SSHO[@]}" -P 2223 test/setup-vulnerable.sh harden-web.sh sysadmin@127.0.0.1:
  "${SSH[@]}" 'sudo bash setup-vulnerable.sh' >/dev/null 2>&1 || { echo "setup gagal"; exit 1; }
fi

step "1. SERANGAN SEBELUM HARDENING (dari luar server)"
FORCE_COLOR=1 bash test/attack-demo.sh | save web-attack-before.txt
step "2. AUDIT SEBELUM HARDENING"
"${SSH[@]}" 'sudo FORCE_COLOR=1 bash harden-web.sh audit' | save web-audit-before.txt
step "3. APPLY HARDENING"
"${SSH[@]}" 'time sudo FORCE_COLOR=1 bash harden-web.sh apply' | save web-apply.txt
step "4. SERANGAN YANG SAMA SETELAH HARDENING"
sleep 40 # biarkan kuota rate limit login pulih supaya terlihat batasnya bekerja
FORCE_COLOR=1 bash test/attack-demo.sh | save web-attack-after.txt
step "5. PENGUNJUNG BIASA: SITUS TETAP BERFUNGSI"
sleep 40 # kuota rate limit login pulih lagi setelah simulasi brute force
FORCE_COLOR=1 bash test/verify-site.sh | save web-site-works.txt
step "6. APPLY KEDUA KALI (harus aman: tidak ada yang diubah)"
"${SSH[@]}" 'sudo FORCE_COLOR=1 bash harden-web.sh apply' | tail -3 | save web-reapply.txt
sleep 1 # tunggu tee di process substitution selesai menulis
