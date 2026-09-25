# MINA Low-Spec Deployment Runbook — low-spec laptop

> Panduan eksekusi uji coba production untuk laptop lawas (Bay Trail,
> RAM terbatas). Ikuti urutan; setiap langkah punya verifikasi.

**Target:** daemon MINA stabil, RAM ≤ 100MB, CPU low-priority, tidak freeze.

---

## 0. Persiapan (5 menit)

```bash
# Cek resource laptop
free -h                    # RAM tersedia
nproc                      # jumlah core (example: 2)
python3 --version          # butuh 3.8+

# Install dependensi MINIMAL (hemat disk & RAM)
sudo apt update
sudo apt install -y python3-pip
pip3 install --user psutil pyyaml     # WAJIB (kecil)
# JANGAN install pyautogui di laptop low-spec — Tier-2 sudah di-disable
```

**Estimasi RAM:** daemon + psutil ≈ **25–35 MB RSS** (terverifikasi).

---

## 1. Siapkan kredensial

**Cara baru (v1.3.0) — via Web UI (direkomendasikan, tidak perlu generate manual):**

```bash
cd the repository root

# Jalankan daemon TANPA env credentials → mode setup:
python3 scripts/mina_daemon.py --port 8765
# Banner menampilkan: SETUP MODE + SETUP TOKEN (one-time)
#   SETUP TOKEN (one-time): xxxxxxxxxxxxxxxx
```

Buka browser **di laptop low-spec**: `http://127.0.0.1:8765/ui/`

1. Halaman **setup** muncul (hanya sekali, butuh setup token dari log)
2. Buat username + password (disimpan sebagai PBKDF2 hash di `~/.mina/auth.json`)
3. **Login** → dashboard
4. Klik **"⟳ Generate API & Secret Key"** → kunci baru langsung aktif
5. **SALIN SEKARANG** — secret ditampilkan **satu kali saja**;
   refresh/close → hanya `mina_sk_********` yang tampil selamanya

```bash
# Salin kredensial yang ditampilkan ke .env (untuk dipakai Hermes side):
cp .env.example .env
# MINA_API_KEY=mina_sk_...        ← dari tampilan satu-kali
# MINA_HMAC_SECRET=...            ← dari tampilan satu-kali
chmod 600 .env
```

> Kredensial tersimpan otomatis di `~/.mina/credentials.env` (chmod 600) dan
> dimuat daemon saat start — `.env` di atas hanya untuk sisi Hermes
> (`send_command.py`).

**Cara lama (tetap didukung) — generate manual:**

```bash
cp .env.example .env
python3 -c "import secrets; print('MINA_API_KEY=mina_sk_' + secrets.token_urlsafe(32))"
python3 -c "import secrets; print('MINA_HMAC_SECRET=' + secrets.token_hex(32))"
nano .env        # isi kedua nilai + MINA_TUNNEL_URL
chmod 600 .env
```

**Lupa password?** Reset akun (kredensial tetap):
```bash
rm ~/.mina/auth.json          # hapus akun
# restart daemon → mode setup lagi dengan token baru dari log
```

**Matikan Web UI sepenuhnya** (kalau tidak dipakai): `MINA_WEBUI=off` di `.env`/unit.

---

## 2. Verifikasi profil low-spec aktif

```bash
# Test cepat tanpa service (foreground, Ctrl+C untuk stop)
export $(grep -v '^#' .env | xargs)
python3 scripts/mina_daemon.py --port 8765
```

**Yang harus muncul di banner:**
```
Profile:  status_cpu_sample=0.3s, cmd_timeout=20s, dashboard_refresh=60s
Tier-2:   DISABLED (tier2_disabled_by_config) — Tier-1 capabilities remain active
```

Jika Tier-2 masih `enabled` → cek `config/mina.yaml` blok `performance:`.

---

## 3. Install sebagai service (pilih SATU)

### Opsi A — User service (REKOMENDASI untuk laptop desktop)

GUI actions (`open_app`, `lock`, `dashboard`) bekerja penuh karena service
berjalan di dalam sesi desktop.

```bash
# Aktifkan linger agar service jalan saat boot tanpa login
loginctl enable-linger $USER

# Install (TANPA sudo)
bash scripts/install_service.sh --user
```

### Opsi B — System service (headless / selalu-on)

```bash
# Install (dengan sudo)
sudo bash scripts/install_service.sh
```

> Catatan: di Opsi B, `open_app`/`dashboard` butuh environment desktop —
> uncomment blok `Environment=DISPLAY...` di unit (lihat
> `scripts/mina-daemon.service.example`). Power actions sudah dibantu
> polkit rule otomatis (`/etc/polkit-1/rules.d/49-mina-power.rules`).

---

## 4. Verifikasi resource limit BENAR-BENAR aktif

```bash
# User service:
systemctl --user show mina-daemon -p MemoryMax -p MemoryHigh -p CPUWeight -p Nice -p OOMPolicy
# System service:
systemctl show mina-daemon -p MemoryMax -p MemoryHigh -p CPUWeight -p Nice -p OOMPolicy

# Ekspektasi output:
#   MemoryMax=104857600      (100 MB)
#   MemoryHigh=83886080      (80 MB)
#   CPUWeight=20
#   Nice=10
#   OOMPolicy=continue

# Pemakaian nyata:
systemd-cgtop -1 --order=memory | grep -i mina
# atau:
ps -o pid,rss,nice,cmd -p $(pgrep -f mina_daemon | head -1)
# Ekspektasi RSS: 25-35 MB (cap 100 MB — headroom 3x)
```

**Test OOM (opsional, membuktikan cap bekerja):**
```bash
systemd-run --user --scope -p MemoryMax=100M -p MemorySwapMax=0 -- \
  python3 -c "bytearray(200*1024*1024)"
# Harus mati dengan "Killed" (exit 137) — cap ditegakkan.
```

---

## 5. Test fungsional (dari Hermes / laptop lain)

```bash
cd the repository root
export $(grep -v '^#' .env | xargs)

# Health check
curl http://127.0.0.1:8765/health

# Status (harus tampil tier2_enabled: false + tier2_reason)
python3 scripts/send_command.py --nl "status" \
  --tunnel-url $MINA_TUNNEL_URL --api-key $MINA_API_KEY --hmac-secret $MINA_HMAC_SECRET

# Tier-1 (aman di laptop low-spec):
python3 scripts/send_command.py --nl "kunci layar" ...
python3 scripts/send_command.py --nl "screenshot" ...
python3 scripts/send_command.py --nl "buka aplikasi files" ...
python3 scripts/send_command.py --nl "tampilkan dashboard" ...   # refresh 60s

# Tier-2 (harus DEGRADASI BERSIH, bukan crash):
python3 scripts/send_command.py --nl "ketik halo" ...
# Ekspektasi: {"ok": false, "error": "tier2_disabled_by_config", ...}
```

---

## 6. Monitor selama uji coba

```bash
# RAM daemon real-time (watch tiap 2 detik)
watch -n 2 'ps -o pid,rss,pcpu,nice -p $(pgrep -f mina_daemon | head -1)'

# Log service
journalctl --user -u mina-daemon -f     # user mode
journalctl -u mina-daemon -f            # system mode

# Cek OOM events (jika ada yang ter-kill)
dmesg | grep -i 'oom\|killed process' | tail -5
journalctl --user -u mina-daemon | grep -i 'memory\|tier2' | tail -10
```

---

## 7. Tuning darurat (jika masih berat)

Edit `.env` atau `config/mina.yaml`, lalu restart:

| Gejala | Solusi |
|--------|--------|
| RAM naik > 80MB | `MINA_TIER2=off` (sudah default), turunkan `MemoryHigh=64M` |
| CPU spike saat `status` | `MINA_STATUS_CPU_INTERVAL=0.1` |
| Dashboard berat | `MINA_DASHBOARD_REFRESH=120` |
| Perintah lama timeout | `MINA_CMD_TIMEOUT=15` |
| Laptop masih lag | Uncomment `CPUQuota=25%` di unit, `systemctl --user daemon-reload && systemctl --user restart mina-daemon` |

```bash
# Restart setelah edit
systemctl --user restart mina-daemon   # atau tanpa --user untuk system mode
```

---

## 8. Rollback / uninstall

```bash
# User mode
systemctl --user stop mina-daemon
systemctl --user disable mina-daemon
rm ~/.config/systemd/user/mina-daemon.service ~/.mina/mina.env
systemctl --user daemon-reload

# System mode
sudo systemctl stop mina-daemon
sudo systemctl disable mina-daemon
sudo rm /etc/systemd/system/mina-daemon.service /etc/mina/mina.env
sudo rm -f /etc/polkit-1/rules.d/49-mina-power.rules
sudo systemctl daemon-reload
```

---

## Checklist cepat malam ini

- [ ] `pip3 install --user psutil pyyaml` (JANGAN pyautogui)
- [ ] Foreground test → banner menunjukkan `Tier-2: DISABLED` + profile low-spec
- [ ] **Web UI**: buka `http://127.0.0.1:8765/ui/` → setup (token dari log) → login
- [ ] **Generate credentials** → salin secret SEKARANG (tampil 1× saja)
- [ ] Refresh dashboard → pastikan hanya `mina_sk_********` yang tampil
- [ ] Isi `.env` (API key + HMAC + tunnel URL) dari tampilan satu-kali, `chmod 600`
- [ ] `install_service.sh --user` + `loginctl enable-linger $USER`
- [ ] `systemctl --user show` → MemoryMax=104857600, Nice=10, CPUWeight=20
- [ ] RSS daemon 25–35 MB
- [ ] `status` OK, `kunci layar` OK, `ketik` → degradasi bersih (bukan crash)
- [ ] Dashboard refresh 60s (bukan 30s)
- [ ] `systemctl --user restart mina-daemon` → harus selesai < 2 detik (shutdown fix)
