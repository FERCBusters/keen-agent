#!/bin/sh
set -eu
. /etc/os-release
case "$ID:$VERSION_ID" in
 debian:12) suite=bookworm; revision="deb12u1.bookworm" ;;
 debian:13) suite=trixie; revision="deb13u1.trixie" ;;
 ubuntu:22.04) suite=jammy; revision="ubuntu22.04.jammy" ;;
 ubuntu:24.04) suite=noble; revision="ubuntu24.04.noble" ;;
 ubuntu:26.04) suite=resolute; revision="ubuntu26.04.resolute" ;;
 *) echo "Unsupported distribution/release: $ID $VERSION_ID" >&2; exit 1 ;;
esac
arch=$(dpkg --print-architecture)
root=$(mktemp -d)
install -D -m 0755 dist/keen-setup-helper "$root/usr/libexec/keen-setup-helper"
install -D -m 0644 packaging/keen-workstation.service "$root/lib/systemd/system/keen-workstation.service"
setup_dep=''
if [ -d dist/setup-app ]; then
 install -d "$root/opt/keen-setup"
 cp -a dist/setup-app/. "$root/opt/keen-setup/"
 chmod 4755 "$root/opt/keen-setup/chrome-sandbox"
 install -D -m 0644 packaging/keen-setup.desktop "$root/usr/share/applications/keen-setup.desktop"
 setup_dep=', polkitd, pkexec, libgtk-3-0t64 | libgtk-3-0, libnss3, libasound2t64 | libasound2, libgbm1, libxss1, libatk-bridge2.0-0t64 | libatk-bridge2.0-0'
fi
install -D -m 0755 dist/keen-agent "$root/usr/bin/keen-agent"
install -D -m 0640 examples/config.yaml "$root/etc/keen-agent/config.yaml"
install -D -m 0644 packaging/keen-agent.service "$root/lib/systemd/system/keen-agent.service"
sed -i 's|/usr/local/bin/keen-agent|/usr/bin/keen-agent|' "$root/lib/systemd/system/keen-agent.service"
for unit in keen-posture-host.service keen-posture-host.timer; do
 install -D -m 0644 "packaging/$unit" "$root/lib/systemd/system/$unit"
done
for unit in keen-posture-session.service keen-posture-session.timer; do
 install -D -m 0644 "packaging/$unit" "$root/usr/lib/systemd/user/$unit"
done
sed -i 's|/usr/local/bin/keen-agent|/usr/bin/keen-agent|' "$root/lib/systemd/system/keen-posture-host.service" "$root/usr/lib/systemd/user/keen-posture-session.service"
install -D -m 0644 packaging/keen-posture-session.desktop "$root/usr/share/doc/keen-agent/keen-posture-session.desktop"
install -D -m 0644 examples/posture.yaml "$root/usr/share/doc/keen-agent/examples/posture.yaml"
install -D -m 0644 docs/posture-linux.md "$root/usr/share/doc/keen-agent/posture.md"
install -d "$root/usr/share/doc/keen-agent" "$root/DEBIAN"
cp LICENSE NOTICE README.md "$root/usr/share/doc/keen-agent/"
cp -r licenses "$root/usr/share/doc/keen-agent/"
cat > "$root/DEBIAN/control" <<EOF
Package: keen-agent
Version: 0.1.10-1+${revision}
Architecture: $arch
Maintainer: KEEN maintainers <mig5@mig5.net>
Depends: ca-certificates, passwd, systemd${setup_dep}
Section: admin
Priority: optional
Description: KEEN evidence log collection agent
 Durable OTLP/HTTP evidence collection with per-agent credentials.
EOF
printf '/etc/keen-agent/config.yaml\n' > "$root/DEBIAN/conffiles"
{ printf '#!/bin/sh\nset -eu\n[ "$1" = configure ] || exit 0\n'; cat packaging/setup-account.sh; } > "$root/DEBIAN/postinst"
cat > "$root/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
 systemctl disable --now keen-workstation.service keen-agent.service keen-posture-host.timer keen-posture-host.service || true
fi
EOF
cat > "$root/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -eu
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
# Credentials, spool and account are retained, including on purge.
EOF
chmod 0755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm" "$root/DEBIAN/postrm"
mkdir -p /out
dpkg-deb --root-owner-group --build "$root" "/out/keen-agent_0.1.10-1+${revision}_${arch}.deb"
