#!/usr/bin/env bash
# dual-ovpn.sh — OpenVPN dual-mode (Cert & PAM) with Q&A-style menu
# Supports: Ubuntu 18+ and Debian 10+, run as root.

set -euo pipefail

die(){ echo "ERROR: $*" >&2; exit 1; }
need_root(){ [[ $EUID -eq 0 ]] || die "jalankan sebagai root"; }
need_tun(){ [[ -e /dev/net/tun ]] || die "/dev/net/tun tidak tersedia (aktifkan TUN)"; }

need_root
need_tun

# ===== OS detection (Ubuntu 18+ or Debian 10+) =====
[[ -r /etc/os-release ]] || die "tidak menemukan /etc/os-release"
. /etc/os-release
get_major(){ echo "$1" | sed 's/[^0-9].*$//'; }
MAJOR="$(get_major "${VERSION_ID:-0}")"
FAMILY=""
if [[ "${ID:-}" == "ubuntu" || "${ID_LIKE:-}" =~ ubuntu ]]; then
  FAMILY="ubuntu"
elif [[ "${ID:-}" == "debian" || "${ID_LIKE:-}" =~ debian ]]; then
  FAMILY="debian"
fi
[[ -n "$FAMILY" ]] || die "skrip ini untuk keluarga Ubuntu/Debian"
if [[ "$FAMILY" == "ubuntu" ]]; then
  [[ "$MAJOR" -ge 18 ]] || die "butuh Ubuntu 18.04+"
else
  [[ "$MAJOR" -ge 10 ]] || die "butuh Debian 10+"
fi

# ===== Default Konfigurasi =====
# Server A (certificate-based)
CERT_PORT="${CERT_PORT:-1194}"
CERT_PROTO="${CERT_PROTO:-udp}"
CERT_DEV="${CERT_DEV:-tun0}"
CERT_NET="${CERT_NET:-10.9.0.0}"
CERT_MASK="${CERT_MASK:-255.255.255.0}"
CERT_AUTH="${CERT_AUTH:-SHA256}"
CERT_DATA_CIPHERS="${CERT_DATA_CIPHERS:-AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305}"
CERT_DATA_FALLBACK="${CERT_DATA_FALLBACK:-AES-128-GCM}"

# Server B (PAM username/password, TANPA tls-auth/crypt) — /24 + static IPs
LOGIN_PORT="${LOGIN_PORT:-1195}"
LOGIN_PROTO="${LOGIN_PROTO:-tcp}"   # tcp recommended for PAM
LOGIN_DEV="${LOGIN_DEV:-tun1}"
LOGIN_NET="${LOGIN_NET:-10.8.0.0}"
LOGIN_MASK="${LOGIN_MASK:-255.255.255.0}"
LOGIN_CIPHER="${LOGIN_CIPHER:-AES-128-CBC}" # untuk MikroTik ROS6 bisa ubah ke BF-CBC
LOGIN_AUTH="${LOGIN_AUTH:-SHA1}"
LOGIN_DATA_CIPHERS="${LOGIN_DATA_CIPHERS:-${LOGIN_CIPHER}}"
LOGIN_DATA_FALLBACK="${LOGIN_DATA_FALLBACK:-${LOGIN_CIPHER}}"
PAM_IP_START_LASTOCTET="${PAM_IP_START_LASTOCTET:-10}" # mulai 10.8.0.10

CLIENT_DIR="/etc/openvpn/clients"
SERVER_CN="server"
CCD_LOGIN_DIR="/etc/openvpn/ccd-login"
IPP_LOGIN_FILE="/etc/openvpn/ipp-login.txt"
ENDPOINT_FILE="/etc/openvpn/server_endpoint.txt"   # simpan IP/hostname publik

# ===== Util =====
pam_path() {
  local p
  for p in \
    /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so \
    /usr/lib/openvpn/openvpn-plugin-auth-pam.so \
    /usr/lib64/openvpn/plugins/openvpn-plugin-auth-pam.so; do
    [[ -f "$p" ]] && { echo "$p"; return; }
  done
  die "openvpn-plugin-auth-pam.so tidak ditemukan"
}
wan_nic() {
  ip -4 route ls | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}
# endpoint handler: tanya user sekali, simpan ke file, bisa diubah via menu
get_endpoint() {
  if [[ -n "${SRV_IP:-}" ]]; then
    echo "$SRV_IP" | tee "$ENDPOINT_FILE" >/dev/null
    cat "$ENDPOINT_FILE"; return
  fi
  if [[ -s "$ENDPOINT_FILE" ]]; then
    cat "$ENDPOINT_FILE"; return
  fi
  local detected=""
  detected="$(curl -fsS https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$detected" ]] || detected="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo -n "Masukkan IP/hostname publik (contoh: ${detected:-vpn.example.com}): "
  read -r endpoint
  if [[ -z "$endpoint" ]]; then
    endpoint="${detected:-YOUR_SERVER_IP_OR_HOSTNAME}"
  fi
  echo "$endpoint" | tee "$ENDPOINT_FILE" >/dev/null
}
set_endpoint_interactive() {
  local current="(belum diset)"
  [[ -s "$ENDPOINT_FILE" ]] && current="$(cat "$ENDPOINT_FILE")"
  echo "Endpoint saat ini: $current"
  echo -n "Isi endpoint baru (IP/hostname): "
  read -r ep
  [[ -z "$ep" ]] && { echo "Kosong, dibatalkan."; return; }
  echo "$ep" | tee "$ENDPOINT_FILE" >/dev/null
  echo "[OK] Endpoint diset ke: $ep"
}

ip_to_int(){ local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24)+(b<<16)+(c<<8)+d )); }
int_to_ip(){ local n=$1; printf "%d.%d.%d.%d" $(((n>>24)&255)) $(((n>>16)&255)) $(((n>>8)&255)) $((n&255)); }
network_base(){ local IFS=.; read -r a b c d <<<"$1"; printf "%d.%d.%d.0" "$a" "$b" "$c"; }
broadcast_ip(){ local IFS=.; read -r a b c d <<<"$(network_base "$1")"; printf "%d.%d.%d.255" "$a" "$b" "$c"; }

# ===== Detector =====
is_openvpn_installed() {
  dpkg -s openvpn >/dev/null 2>&1 || [[ -e /etc/openvpn/server/server-cert.conf || -e /etc/openvpn/server-cert.conf ]]
}

# ===== Easy-RSA via APT =====
install_easyrsa() {
  echo "[*] Install Easy-RSA (APT)…"
  apt-get install -y --no-install-recommends easy-rsa
  mkdir -p /etc/openvpn/easy-rsa
  cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa
  [[ -x /etc/openvpn/easy-rsa/easyrsa ]] || die "Easy-RSA tidak ditemukan setelah instalasi APT."
}

# ===== Installer (sekali jalan) =====
install_all() {
  echo "[*] Install paket…"
  apt-get update -y
  apt-get install -y --no-install-recommends openvpn openssl iptables curl wget ca-certificates lsb-release iptables-persistent

  # Easy-RSA dari APT saja
  install_easyrsa

  echo "[*] Generate CA + Server cert/key + DH…"
  pushd /etc/openvpn/easy-rsa >/dev/null
  cat > vars <<'EOF'
set_var EASYRSA_BATCH "1"
set_var EASYRSA_REQ_CN "ovpn-ca"
set_var EASYRSA_ALGO "rsa"
set_var EASYRSA_KEY_SIZE "2048"
EOF
  ./easyrsa init-pki
  ./easyrsa build-ca nopass
  ./easyrsa build-server-full "server" nopass
  openssl dhparam -out dh.pem 2048
  EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
  popd >/dev/null

  install -m 644 /etc/openvpn/easy-rsa/pki/ca.crt                  /etc/openvpn/ca.crt
  install -m 600 /etc/openvpn/easy-rsa/pki/private/ca.key          /etc/openvpn/ca.key || true
  install -m 644 /etc/openvpn/easy-rsa/pki/issued/${SERVER_CN}.crt /etc/openvpn/server.crt
  install -m 600 /etc/openvpn/easy-rsa/pki/private/${SERVER_CN}.key /etc/openvpn/server.key
  install -m 644 /etc/openvpn/easy-rsa/pki/crl.pem                 /etc/openvpn/crl.pem
  install -m 644 /etc/openvpn/easy-rsa/dh.pem                      /etc/openvpn/dh.pem
  chmod 644 /etc/openvpn/crl.pem
  mkdir -p "$CLIENT_DIR" "$CCD_LOGIN_DIR" /var/log /etc/openvpn/server
  touch "$IPP_LOGIN_FILE"

  echo "[*] Konfigurasi PAM /etc/pam.d/openvpn…"
  cat > /etc/pam.d/openvpn <<'PAM'
auth    required    pam_unix.so shadow nodelay
account required    pam_unix.so
PAM

  local PAM_SO; PAM_SO="$(pam_path)"

  echo "[*] Tulis server CERT config…"
  cat > /etc/openvpn/server/server-cert.conf <<EOF
port ${CERT_PORT}
proto ${CERT_PROTO}
dev ${CERT_DEV}

ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem

verify-client-cert require
remote-cert-tls client

data-ciphers ${CERT_DATA_CIPHERS}
data-ciphers-fallback ${CERT_DATA_FALLBACK}
auth ${CERT_AUTH}

topology subnet
server ${CERT_NET} ${CERT_MASK}
ifconfig-pool-persist /etc/openvpn/ipp-cert.txt

keepalive 10 120
persist-key
persist-tun
crl-verify /etc/openvpn/crl.pem
status /var/log/openvpn-cert-status.log
log-append /var/log/openvpn-cert.log
verb 3
EOF

  echo "[*] Tulis server PAM config… (tanpa tls-crypt/auth) — /24 + CCD"
  cat > /etc/openvpn/server/server-login.conf <<EOF
port ${LOGIN_PORT}
proto ${LOGIN_PROTO}
dev ${LOGIN_DEV}

ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem

auth ${LOGIN_AUTH}
cipher ${LOGIN_CIPHER}
data-ciphers ${LOGIN_DATA_CIPHERS}
data-ciphers-fallback ${LOGIN_DATA_FALLBACK}

plugin ${PAM_SO} login
verify-client-cert none
username-as-common-name
topology subnet
client-config-dir ${CCD_LOGIN_DIR}

server ${LOGIN_NET} ${LOGIN_MASK}
ifconfig-pool-persist ${IPP_LOGIN_FILE}

keepalive 10 120
persist-key
persist-tun
crl-verify /etc/openvpn/crl.pem
status /var/log/openvpn-login-status.log
log-append /var/log/openvpn-login.log
verb 3
EOF

  # Juga siapkan file untuk layout lama (/etc/openvpn/*.conf)
  cp -f /etc/openvpn/server/server-cert.conf  /etc/openvpn/server-cert.conf
  cp -f /etc/openvpn/server/server-login.conf /etc/openvpn/server-login.conf

  echo "[*] Enable IP forwarding…"
  mkdir -p /etc/sysctl.d
  echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-openvpn-forward.conf
  sysctl --system >/dev/null

  echo "[*] Atur iptables (MASQUERADE)…"
  local NIC; NIC="$(wan_nic)"; [[ -n "$NIC" ]] || die "gagal deteksi NIC"
  # bersihkan sisa lama
  iptables -t nat -D POSTROUTING -s ${CERT_NET}/${CERT_MASK} -o ${NIC} -j MASQUERADE 2>/dev/null || true
  iptables -t nat -D POSTROUTING -s ${LOGIN_NET}/${LOGIN_MASK} -o ${NIC} -j MASQUERADE 2>/dev/null || true
  iptables -D INPUT -i ${CERT_DEV} -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -i ${LOGIN_DEV} -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i ${NIC} -o ${CERT_DEV} -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i ${CERT_DEV} -o ${NIC} -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i ${NIC} -o ${LOGIN_DEV} -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i ${LOGIN_DEV} -o ${NIC} -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -i ${NIC} -p ${CERT_PROTO} --dport ${CERT_PORT} -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -i ${NIC} -p ${LOGIN_PROTO} --dport ${LOGIN_PORT} -j ACCEPT 2>/dev/null || true
  # baru
  iptables -t nat -I POSTROUTING 1 -s ${CERT_NET}/${CERT_MASK} -o ${NIC} -j MASQUERADE
  iptables -t nat -I POSTROUTING 1 -s ${LOGIN_NET}/${LOGIN_MASK} -o ${NIC} -j MASQUERADE
  iptables -I INPUT 1 -i ${CERT_DEV} -j ACCEPT
  iptables -I INPUT 1 -i ${LOGIN_DEV} -j ACCEPT
  iptables -I FORWARD 1 -i ${NIC} -o ${CERT_DEV} -j ACCEPT
  iptables -I FORWARD 1 -i ${CERT_DEV} -o ${NIC} -j ACCEPT
  iptables -I FORWARD 1 -i ${NIC} -o ${LOGIN_DEV} -j ACCEPT
  iptables -I FORWARD 1 -i ${LOGIN_DEV} -o ${NIC} -j ACCEPT
  iptables -I INPUT 1 -i ${NIC} -p ${CERT_PROTO} --dport ${CERT_PORT} -j ACCEPT
  iptables -I INPUT 1 -i ${NIC} -p ${LOGIN_PROTO} --dport ${LOGIN_PORT} -j ACCEPT
  netfilter-persistent save

  echo "[*] Set endpoint untuk client…"
  get_endpoint >/dev/null

  echo "[*] Enable services…"
  enable_units

  echo
  echo ">>> Instalasi selesai. Dua server aktif:"
  echo "    - CERT : ${CERT_PORT}/${CERT_PROTO}  cfg: /etc/openvpn/server/server-cert.conf"
  echo "    - PAM  : ${LOGIN_PORT}/${LOGIN_PROTO} cfg: /etc/openvpn/server/server-login.conf (subnet ${LOGIN_NET} ${LOGIN_MASK})"
  echo "    - Endpoint file: ${ENDPOINT_FILE} ($(cat ${ENDPOINT_FILE}))"
  echo
}

# ===== Enable services (dukung 2 layout) =====
enable_units() {
  systemctl daemon-reload
  if systemctl list-unit-files | grep -q '^openvpn-server@\.service'; then
    # Layout baru: /etc/openvpn/server/*.conf
    systemctl disable --now openvpn@server-cert  2>/dev/null || true
    systemctl disable --now openvpn@server-login 2>/dev/null || true
    systemctl enable --now openvpn-server@server-cert
    systemctl enable --now openvpn-server@server-login
  elif systemctl list-unit-files | grep -q '^openvpn@\.service'; then
    # Layout lama: /etc/openvpn/*.conf
    systemctl enable --now openvpn@server-cert
    systemctl enable --now openvpn@server-login
  else
    die "Tidak menemukan unit openvpn-server@ atau openvpn@ di systemd."
  fi
}

# ===== Client Builders =====
make_cert_ovpn() {
  local U="$1"
  local SRV_HOST; SRV_HOST="$(get_endpoint)"
  local OUT="${CLIENT_DIR}/${U}-cert.ovpn"

  cat > "$OUT" <<EOF
client
dev ${CERT_DEV}
proto $( [[ "${CERT_PROTO}" == "udp" ]] && echo "udp" || echo "tcp-client" )
remote ${SRV_HOST} ${CERT_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verb 3

auth ${CERT_AUTH}
cipher AES-128-GCM

<ca>
$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' /etc/openvpn/ca.crt)
</ca>
<cert>
$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "/etc/openvpn/easy-rsa/pki/issued/${U}.crt")
</cert>
<key>
$(cat "/etc/openvpn/easy-rsa/pki/private/${U}.key")
</key>
EOF
  chmod 600 "$OUT"
  echo "[OK] Cert client dibuat: $OUT"
}

make_pam_ovpn() {
  local U="$1"
  local SRV_HOST; SRV_HOST="$(get_endpoint)"
  local OUT="${CLIENT_DIR}/${U}-pam.ovpn"
  cat > "$OUT" <<EOF
client
dev ${LOGIN_DEV}
proto $( [[ "${LOGIN_PROTO}" == "udp" ]] && echo "udp" || echo "tcp-client" )
remote ${SRV_HOST} ${LOGIN_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
verb 3

cipher ${LOGIN_CIPHER}
auth ${LOGIN_AUTH}

<ca>
$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' /etc/openvpn/ca.crt)
</ca>
EOF
  chmod 600 "$OUT"
  echo "[OK] PAM client dibuat: $OUT"
}

# ===== Alokasi IP Statis untuk PAM =====
ensure_ipp_and_ccd(){ mkdir -p "$CCD_LOGIN_DIR"; touch "$IPP_LOGIN_FILE"; }
username_has_ip(){ local U="$1"; grep -E "^${U}," "$IPP_LOGIN_FILE" | awk -F, '{print $2}' | head -1; }
ip_in_use(){ local ip="$1"; grep -qE ",${ip}(\s|$)" "$IPP_LOGIN_FILE"; }
alloc_next_ip(){
  local base=$(network_base "$LOGIN_NET")
  local start_octet="$PAM_IP_START_LASTOCTET"
  local IFS=.; read -r a b c d <<<"$base"
  local start_ip="${a}.${b}.${c}.${start_octet}"
  local n=$(ip_to_int "$start_ip")
  local bcast=$(broadcast_ip "$LOGIN_NET")
  local n_bcast=$(ip_to_int "$bcast")
  while (( n < n_bcast )); do
    local cand="$(int_to_ip "$n")"
    if [[ "$cand" != "${a}.${b}.${c}.0" && "$cand" != "${a}.${b}.${c}.1" ]]; then
      if ! ip_in_use "$cand"; then echo "$cand"; return 0; fi
    fi
    ((n++))
  done
  return 1
}
assign_static_ip_for_user(){
  local U="$1"
  ensure_ipp_and_ccd
  local current_ip; current_ip="$(username_has_ip "$U")"
  if [[ -n "$current_ip" ]]; then
    echo "[i] ${U} sudah memiliki IP ${current_ip}."
    echo "ifconfig-push ${current_ip} ${LOGIN_MASK}" > "${CCD_LOGIN_DIR}/${U}"
    return 0
  fi
  local new_ip; new_ip="$(alloc_next_ip)" || die "habis IP di ${LOGIN_NET}/${LOGIN_MASK}"
  echo "${U},${new_ip}" >> "$IPP_LOGIN_FILE"
  echo "ifconfig-push ${new_ip} ${LOGIN_MASK}" > "${CCD_LOGIN_DIR}/${U}"
  echo "[OK] Alokasi IP statik PAM untuk ${U}: ${new_ip}"
}

add_cert_user() {
  local U="$1"
  [[ -n "$U" ]] || { echo "Username tidak boleh kosong"; return 1; }
  mkdir -p "$CLIENT_DIR"
  if [[ -e /etc/openvpn/easy-rsa/pki/index.txt ]] && grep -q "/CN=${U}$" /etc/openvpn/easy-rsa/pki/index.txt; then
    echo "User cert '${U}' sudah ada. Membuat ulang file .ovpn…"
    make_cert_ovpn "$U"; return 0
  fi
  pushd /etc/openvpn/easy-rsa >/dev/null
  ./easyrsa build-client-full "$U" nopass
  popd >/dev/null
  make_cert_ovpn "$U"
}

# ===== PAM user simple (useradd + chpasswd, shell nologin) + STATIC IP =====
add_pam_user() {
  local U="$1"
  [[ -n "$U" ]] || { echo "Username tidak boleh kosong"; return 1; }
  local P1 P2
  read -s -p "Password baru untuk ${U}: " P1; echo
  read -s -p "Ulangi password: " P2; echo
  [[ "$P1" == "$P2" ]] || { echo "Password tidak cocok"; return 1; }

  if id "$U" >/dev/null 2>&1; then
    echo "${U}:${P1}" | chpasswd
    chsh -s /usr/sbin/nologin "$U"
  else
    useradd -M -s /usr/sbin/nologin "$U"
    echo "${U}:${P1}" | chpasswd
  fi

  assign_static_ip_for_user "$U"
  mkdir -p "$CLIENT_DIR"
  make_pam_ovpn "$U"
}

remove_openvpn() {
  echo -n "Yakin hapus OpenVPN + config? [y/N]: "
  read -r ans
  [[ "${ans,,}" == "y" ]] || { echo "Batal."; return; }

  # Stop & disable kedua layout
  systemctl disable --now openvpn-server@server-cert 2>/dev/null || true
  systemctl disable --now openvpn-server@server-login 2>/dev/null || true
  systemctl disable --now openvpn@server-cert 2>/dev/null || true
  systemctl disable --now openvpn@server-login 2>/dev/null || true

  local NIC; NIC="$(wan_nic)"
  iptables -t nat -D POSTROUTING -s ${CERT_NET}/${CERT_MASK} -o ${NIC} -j MASQUERADE 2>/dev/null || true
  iptables -t nat -D POSTROUTING -s ${LOGIN_NET}/${LOGIN_MASK} -o ${NIC} -j MASQUERADE 2>/dev/null || true

  rm -rf /etc/openvpn/server/server-cert.conf /etc/openvpn/server/server-login.conf
  rm -rf /etc/openvpn/server-cert.conf /etc/openvpn/server-login.conf
  rm -rf /etc/openvpn/easy-rsa /etc/openvpn/clients /etc/openvpn/ca.crt /etc/openvpn/server.crt /etc/openvpn/server.key /etc/openvpn/dh.pem /etc/openvpn/crl.pem \
         /etc/openvpn/ipp-cert.txt ${IPP_LOGIN_FILE} ${CCD_LOGIN_DIR} ${ENDPOINT_FILE}

  apt-get remove --purge -y openvpn || true
  echo "OpenVPN dan konfigurasi dihapus."
}

# ===== Enable services (dukung 2 layout) =====
enable_units() {
  systemctl daemon-reload
  if systemctl list-unit-files | grep -q '^openvpn-server@\.service'; then
    # Layout baru: /etc/openvpn/server/*.conf
    systemctl disable --now openvpn@server-cert  2>/dev/null || true
    systemctl disable --now openvpn@server-login 2>/dev/null || true
    systemctl enable --now openvpn-server@server-cert
    systemctl enable --now openvpn-server@server-login
  elif systemctl list-unit-files | grep -q '^openvpn@\.service'; then
    # Layout lama: /etc/openvpn/*.conf
    systemctl enable --now openvpn@server-cert
    systemctl enable --now openvpn@server-login
  else
    die "Tidak menemukan unit openvpn-server@ atau openvpn@ di systemd."
  fi
}

# ===== Menu =====
menu() {
  echo
  echo "=== OpenVPN Dual-Mode ==="
  echo "1) Add Client Cert"
  echo "2) Add Client PAM (static IP)"
  echo "3) Remove OpenVPN"
  echo "4) Change Endpoint"
  echo "5) Keluar"
  echo -n "Pilih [1-5]: "
  read -r ch
  case "$ch" in
    1) read -rp "Username CERT: " U; add_cert_user "$U" ;;
    2) read -rp "Username PAM : " U; add_pam_user "$U" ;;
    3) remove_openvpn ;;
    4) set_endpoint_interactive ;;
    5) exit 0 ;;
    *) echo "Pilihan tidak valid" ;;
  esac
}

# ===== Main =====
if is_openvpn_installed; then
  echo "[i] OpenVPN terdeteksi. Masuk menu."
  while true; do menu; done
else
  echo "[i] OpenVPN belum terpasang/tersiap."
  read -rp "Ingin instal & setup dual-server sekarang? [Y/n]: " yn
  yn="${yn:-Y}"
  if [[ "${yn,,}" == "y" || "${yn,,}" == "yes" ]]; then
    install_all
    echo
    echo "[i] Instalasi selesai. Masuk menu."
    while true; do menu; done
  else
    echo "Batal."
    exit 0
  fi
fi
