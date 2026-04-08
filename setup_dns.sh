#!/bin/sh
set -e

DEFAULT_PORT="5353"
PORT="${1:-$DEFAULT_PORT}"
LISTEN="127.0.0.1:${PORT}"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (try: sudo $0 $*)" >&2
    exit 1
fi

# Detect DNS backend and configure accordingly.

setup_systemd_resolved() {
    DROPIN_DIR="/etc/systemd/resolved.conf.d"
    DROPIN_PATH="${DROPIN_DIR}/pulse.conf"

    mkdir -p "$DROPIN_DIR"
    cat > "$DROPIN_PATH" <<EOF
[Resolve]
DNS=${LISTEN}
Domains=~pulse
EOF

    systemctl restart systemd-resolved
    echo "configured systemd-resolved"
    echo "  wrote ${DROPIN_PATH}"
    echo ""
    echo "to undo:"
    echo "  sudo rm ${DROPIN_PATH}"
    echo "  sudo systemctl restart systemd-resolved"
}

setup_resolvconf() {
    CONF="/etc/resolvconf/resolv.conf.d/head"
    if [ ! -d "$(dirname "$CONF")" ]; then
        CONF="/etc/resolvconf.conf"
    fi

    # Append dnsmasq-style conditional forwarding if available.
    if command -v dnsmasq >/dev/null 2>&1; then
        DNSMASQ_CONF="/etc/dnsmasq.d/pulse.conf"
        echo "server=/pulse/${LISTEN}" > "$DNSMASQ_CONF"
        if command -v systemctl >/dev/null 2>&1; then
            systemctl restart dnsmasq 2>/dev/null || service dnsmasq restart
        else
            service dnsmasq restart
        fi
        echo "configured dnsmasq"
        echo "  wrote ${DNSMASQ_CONF}"
        echo ""
        echo "to undo:"
        echo "  sudo rm ${DNSMASQ_CONF}"
        echo "  sudo systemctl restart dnsmasq"
        return
    fi

    # Fall back to prepending nameserver to resolvconf head.
    if [ -f "$CONF" ]; then
        if grep -q "# pulse-dns" "$CONF" 2>/dev/null; then
            echo "pulse DNS already configured in ${CONF}"
            return
        fi
    fi

    printf "nameserver %s # pulse-dns\n" "127.0.0.1" >> "$CONF"
    resolvconf -u
    echo "configured resolvconf"
    echo "  appended nameserver to ${CONF}"
    echo "  note: this sends ALL queries to 127.0.0.1 — only .pulse will resolve"
    echo ""
    echo "to undo:"
    echo "  remove the '# pulse-dns' line from ${CONF}"
    echo "  sudo resolvconf -u"
}

setup_networkmanager() {
    DNSMASQ_CONF="/etc/NetworkManager/dnsmasq.d/pulse.conf"
    mkdir -p "$(dirname "$DNSMASQ_CONF")"
    echo "server=/pulse/${LISTEN}" > "$DNSMASQ_CONF"

    # Ensure NM uses dnsmasq as its DNS plugin.
    NM_CONF="/etc/NetworkManager/conf.d/pulse-dns.conf"
    mkdir -p "$(dirname "$NM_CONF")"
    cat > "$NM_CONF" <<EOF
[main]
dns=dnsmasq
EOF

    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart NetworkManager
    else
        service NetworkManager restart 2>/dev/null || service network-manager restart
    fi
    echo "configured NetworkManager + dnsmasq"
    echo "  wrote ${DNSMASQ_CONF}"
    echo "  wrote ${NM_CONF}"
    echo ""
    echo "to undo:"
    echo "  sudo rm ${DNSMASQ_CONF} ${NM_CONF}"
    echo "  sudo systemctl restart NetworkManager"
}

setup_resolv_conf_direct() {
    RESOLV="/etc/resolv.conf"
    if grep -q "# pulse-dns" "$RESOLV" 2>/dev/null; then
        echo "pulse DNS already configured in ${RESOLV}"
        return
    fi

    # Prepend our nameserver (only works for non-managed resolv.conf).
    cp "$RESOLV" "${RESOLV}.pulse-backup"
    printf "nameserver %s # pulse-dns\n" "127.0.0.1" | cat - "$RESOLV" > "${RESOLV}.tmp"
    mv "${RESOLV}.tmp" "$RESOLV"
    echo "configured /etc/resolv.conf directly"
    echo "  backed up to ${RESOLV}.pulse-backup"
    echo "  note: this sends ALL queries to 127.0.0.1 first — only .pulse will resolve there"
    echo ""
    echo "to undo:"
    echo "  sudo mv ${RESOLV}.pulse-backup ${RESOLV}"
}

# Detection order: systemd-resolved > NetworkManager+dnsmasq > resolvconf > direct

if command -v systemctl >/dev/null 2>&1 && systemctl is-active systemd-resolved >/dev/null 2>&1; then
    echo "detected: systemd-resolved"
    setup_systemd_resolved
elif command -v nmcli >/dev/null 2>&1 && nmcli general status >/dev/null 2>&1; then
    echo "detected: NetworkManager"
    setup_networkmanager
elif command -v resolvconf >/dev/null 2>&1; then
    echo "detected: resolvconf"
    setup_resolvconf
else
    echo "detected: plain /etc/resolv.conf"
    setup_resolv_conf_direct
fi

echo ""
echo "done — .pulse domains now resolve through ${LISTEN}"
