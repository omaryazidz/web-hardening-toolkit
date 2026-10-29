# Web Server Hardening: Nginx + WordPress + WAF

Script untuk **mengaudit** lalu **mengamankan** website WordPress di Nginx: header keamanan, TLS modern, blokir file rahasia, anti brute force, dan WAF (ModSecurity + OWASP Core Rule Set). Setiap pemeriksaan dilakukan lewat HTTP/TLS sungguhan, bukan hanya membaca file konfigurasi.

Kasus yang ditangani: website baru dari developer atau hosting biasanya berjalan dengan konfigurasi bawaan. `.env` dan backup database bisa diunduh siapa saja, versi server terlihat, TLS lama masih aktif, dan halaman login bisa ditebak passwordnya tanpa batas.

## Hasil uji (lab)

Diuji di VM **Ubuntu 24.04 LTS** (cloud image resmi) dengan **Nginx 1.24 + PHP-FPM + MariaDB + WordPress terbaru**. Server dibuat dengan kesalahan konfigurasi yang umum ditemukan di server klien. Semua rahasia di dalamnya palsu.

**Skor audit: 0/11 → 11/11** dalam 18 detik.

### Serangan yang sama, sebelum dan sesudah

Dijalankan dari luar server ([`test/attack-demo.sh`](test/attack-demo.sh)):

| Serangan | Sebelum | Sesudah |
|---|---|---|
| Baca versi server | `nginx/1.24.0 (Ubuntu)` | `nginx` |
| Unduh `/.env` | isi terbaca (DB password) | 403 |
| Unduh `/.git/config` | URL repo terbaca | 403 |
| Unduh `/backup.sql` | dump database terunduh | 403 |
| Lihat isi folder `uploads/` | daftar file terbuka | tertutup |
| Eksekusi PHP di `uploads/` (jalur web shell) | PHP berjalan | ditolak |
| `/?author=1` dan REST API user | username `editor1` bocor | 403 |
| SQL injection `?id=1' OR '1'='1` | 200, sampai ke aplikasi | **403, diblokir WAF** |
| XSS `?s=<script>…` | 200, sampai ke aplikasi | **403, diblokir WAF** |
| Tebak password login 20x | 200 × 20 (bebas) | 200 × 6, lalu **429 × 14** |
| TLS 1.0 / 1.1 | diterima | ditolak |

### Situs tetap berfungsi

Hardening yang merusak website itu tidak ada gunanya, jadi ini ikut diuji dari sisi pengunjung biasa ([`test/verify-site.sh`](test/verify-site.sh)):

```
[PASS] Halaman utama tampil (HTTP 200)
[PASS] Halaman artikel terbuka (HTTP 200)
[PASS] Pencarian biasa tidak salah blokir (HTTP 200)
[PASS] Halaman login terbuka (HTTP 200)
```

Menjalankan `apply` untuk kedua kalinya tidak mengubah apa pun (tetap 11/11). Output mentah semua pengujian ada di [`results/`](results/).

## Pemakaian

```bash
sudo ./harden-web.sh audit   # cek saja, tidak mengubah konfigurasi
sudo ./harden-web.sh apply   # perbaiki yang FAIL
```

Webroot, sertifikat TLS, dan socket PHP dibaca otomatis dari konfigurasi Nginx yang sedang berjalan. Kalau file site-nya bukan `/etc/nginx/sites-available/wordpress`, isi variabel `SITE_CONF`.

## Yang dikerjakan

- **TLS**: hanya TLS 1.2/1.3 dengan cipher AEAD, session ticket dimatikan, HTTP dialihkan ke HTTPS.
- **Header**: HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, dan CSP. CSP memakai versi yang aman (`frame-ancestors`, `base-uri`, `object-src`). Pembatasan `script-src` sengaja tidak dipasang karena hampir selalu merusak tema dan plugin WordPress.
- **File sensitif**: semua dotfile (kecuali `.well-known`), ekstensi `.sql .bak .old .env .log .ini` dan sejenisnya diblokir. Directory listing dimatikan.
- **WordPress**: `xmlrpc.php` diblokir, enumerasi username ditutup (REST API user tetap terbuka untuk yang sudah login supaya editor tetap jalan), dan PHP dilarang jalan di `wp-content/uploads`.
- **Anti brute force**: rate limit di `wp-login.php` (10 percobaan per menit, burst 5, balasan 429).
- **WAF**: ModSecurity v3 + OWASP CRS, mode blocking (bawaan paket hanya `DetectionOnly`, yang tidak memblokir apa pun), dengan exclusion rules WordPress dari CRS supaya wp-admin tidak terblokir salah.
- **Ketahanan dasar**: timeout header/body 15 detik dan batas upload 20 MB untuk mengurangi dampak slowloris.

## Pengaman supaya server klien tidak rusak

| Risiko | Pengaman |
|---|---|
| Config Nginx rusak, website mati | Divalidasi dengan `nginx -t` sebelum dipakai. Kalau gagal, `/etc/nginx` otomatis dikembalikan dari backup. Ini benar-benar terjadi saat pengembangan (WAF menolak satu direktif), dan server tetap hidup. |
| Perlu kembali ke kondisi awal | `/etc/nginx` disalin ke `/var/backups/web-hardening-<waktu>/` sebelum diubah. |
| WAF salah blokir pengunjung asli | Exclusion rules WordPress aktif, dan pencarian biasa diuji lolos. |
| Dijalankan berulang | Idempotent: pemeriksaan yang sudah PASS dilewati. |

## Batasan

- Diuji di lab dengan sertifikat self-signed. Nilai publik seperti SSL Labs atau securityheaders.com hanya bisa diambil dari server nyata dengan domain dan sertifikat sungguhan.
- WAF berjalan di paranoia level 1 (bawaan CRS). Situs dengan plugin yang tidak umum (misalnya form builder yang kompleks) mungkin butuh penyesuaian exclusion rule setelah dipantau di `/var/log/nginx/modsec_audit.log`.
- Script mengasumsikan WordPress + PHP-FPM + Nginx. Untuk aplikasi lain (Laravel, Node.js) aturan WordPress-nya perlu disesuaikan.
- Pemeriksaan `uploads_php` membuat file uji sementara di folder uploads lalu langsung menghapusnya, kecuali file `test.php` sudah ada.

## Menjalankan ulang lab

Butuh WSL2 dengan KVM. Perintah ini membuat VM baru, memasang WordPress yang rentan, lalu menjalankan semua tahap di atas (sekitar 3 menit):

```bash
sudo bash test/run-lab.sh
```

## Struktur

```
harden-web.sh            audit + apply
test/setup-vulnerable.sh WordPress + Nginx dengan kesalahan konfigurasi umum
test/attack-demo.sh      simulasi serangan dari luar server
test/verify-site.sh      memastikan situs tetap berfungsi
test/lab-vm.sh           VM Ubuntu via QEMU/KVM
test/run-lab.sh          menjalankan semuanya dan menyimpan hasil ke results/
results/                 output asli dari lab
```
