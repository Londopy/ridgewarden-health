#!/bin/sh
# Install ridgewarden-health on a Linux box that already runs the ridgewarden core.
#
#   curl -fsSL https://github.com/Londopy/ridgewarden-health/releases/latest/download/install.sh | sudo sh
#
# Optional: RIDGEWARDEN_HEALTH_VERSION=0.2.0 to pin a version.
set -eu

REPO=Londopy/ridgewarden-health
BIN=/usr/local/bin/ridgewarden-health

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root (with sudo)." >&2
    exit 1
fi

# the core checks this release's signature, and the app needs the core to run
core=$(command -v ridgewarden || true)
if [ -z "$core" ]; then
    echo "Install the ridgewarden core first: https://github.com/Londopy/ridgewarden" >&2
    exit 1
fi

case "$(uname -m)" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *)
        echo "No build for $(uname -m). 64-bit Raspberry Pi OS and x86_64 Linux are supported." >&2
        exit 1
        ;;
esac

pinned=${RIDGEWARDEN_HEALTH_VERSION:-}
if [ -n "$pinned" ]; then
    tag="v$pinned"
else
    tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
        sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
fi
[ -n "$tag" ] || { echo "Could not find the latest release." >&2; exit 1; }
ver=${tag#v}
file="ridgewarden-health-v$ver-$arch-linux.tar.gz"
base="https://github.com/$REPO/releases/download/$tag"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "Downloading ridgewarden-health $tag for $arch"
for f in "$file" SHA256SUMS.txt SHA256SUMS.txt.sig; do
    curl -fsSL -o "$tmp/$f" "$base/$f"
done

# the installed core checks the signature against the release key it already trusts
(cd "$tmp" && grep " $file\$" SHA256SUMS.txt | sha256sum -c -)
"$core" verify-release "$tmp/SHA256SUMS.txt"
tar -xzf "$tmp/$file" -C "$tmp"
dir="$tmp/ridgewarden-health-v$ver-$arch-linux"

install -m 755 "$dir/ridgewarden-health" "$BIN"
if ! id ridgewarden-health >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/ridgewarden-health --shell /usr/sbin/nologin --user-group ridgewarden-health
fi
usermod -a -G ridgewarden ridgewarden-health
install -d -m 750 -o ridgewarden-health -g ridgewarden-health /var/lib/ridgewarden-health
# an upgrade from when apps ran as the core's user leaves files it owned
chown -R ridgewarden-health:ridgewarden-health /var/lib/ridgewarden-health
if [ ! -f /etc/ridgewarden/health.toml ]; then
    "$BIN" --config /etc/ridgewarden/health.toml init
fi
# its webhook URLs and passphrases are for this app only, not the other apps
# in the ridgewarden group
chown root:ridgewarden-health /etc/ridgewarden/health.toml
chmod 640 /etc/ridgewarden/health.toml

if [ -d /run/systemd/system ]; then
    sed "s#/usr/bin/ridgewarden-health#$BIN#" "$dir/ridgewarden-health.service" >/etc/systemd/system/ridgewarden-health.service
    systemctl daemon-reload
    systemctl enable ridgewarden-health
    if [ -f /etc/ridgewarden/ridgewarden.toml ]; then
        # restart, so an upgrade replaces a running old version
        systemctl restart ridgewarden-health
    else
        echo "Set up the core first (ridgewarden init), then: sudo systemctl start ridgewarden-health"
        exit 0
    fi
    echo "ridgewarden-health is running: http://$(hostname):8791/"
else
    echo "Installed $BIN ($tag). Start it with: $BIN --config /etc/ridgewarden/health.toml run"
fi
