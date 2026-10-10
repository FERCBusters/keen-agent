#!/bin/sh
set -eu
. /etc/os-release
case "$VERSION_ID" in
 12) suite=bookworm ;;
 13) suite=trixie ;;
 *) echo "Unsupported Debian release: $VERSION_ID" >&2; exit 1 ;;
esac
arch=$(dpkg --print-architecture)
root=$(mktemp -d)
install -D -m 0755 dist/keen-agent "$root/usr/bin/keen-agent"
install -D -m 0640 examples/config.yaml "$root/etc/keen-agent/config.yaml"
install -D -m 0644 packaging/keen-agent.service "$root/lib/systemd/system/keen-agent.service"
sed -i 's|/usr/local/bin/keen-agent|/usr/bin/keen-agent|' "$root/lib/systemd/system/keen-agent.service"
install -d "$root/usr/share/doc/keen-agent" "$root/DEBIAN"
cp LICENSE NOTICE README.md "$root/usr/share/doc/keen-agent/"
cp -r licenses "$root/usr/share/doc/keen-agent/"
cat > "$root/DEBIAN/control" <<EOF
Package: keen-agent
Version: 0.1.6-1+deb${VERSION_ID}u1.${suite}
Architecture: $arch
Maintainer: KEEN maintainers <mig5@mig5.net>
Depends: ca-certificates, passwd, systemd
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
 systemctl disable --now keen-agent.service || true
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
dpkg-deb --root-owner-group --build "$root" "/out/keen-agent_0.1.6-1+deb${VERSION_ID}u1.${suite}_${arch}.deb"
