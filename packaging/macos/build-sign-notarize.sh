#!/bin/bash
set -euo pipefail
# Run on macOS with Go, Xcode command-line tools and Developer ID identities.
unsigned=${UNSIGNED:-0}
if [[ "$unsigned" != 1 ]]; then
 : "${APPLICATION_IDENTITY:?Developer ID Application identity required}"
 : "${INSTALLER_IDENTITY:?Developer ID Installer identity required}"
 : "${NOTARY_PROFILE:?notarytool keychain profile required}"
fi
[[ $(uname -s) == Darwin ]] || { echo 'Build on macOS' >&2; exit 1; }
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
# VERSION is the single source of the release version.
version=$(cat VERSION)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid VERSION: $version" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
out="$repo/dist/macos"
mkdir -p "$out" "$work/root/usr/local/libexec" "$work/root/Library/LaunchDaemons" "$work/scripts"
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath -o "$work/keen-posture-$arch" ./cmd/keen-posture
  CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath -o "$work/keen-setup-helper-$arch" ./cmd/keen-setup-helper
done
lipo -create "$work/keen-posture-amd64" "$work/keen-posture-arm64" -output "$work/root/usr/local/libexec/keen-posture"
lipo -create "$work/keen-setup-helper-amd64" "$work/keen-setup-helper-arm64" -output "$work/root/usr/local/libexec/keen-setup-helper"
npm ci --prefix onboarding
npm test --prefix onboarding
SETUP_PLATFORM=darwin SETUP_ARCH=universal npm run package --prefix onboarding
mkdir -p "$work/root/Applications"
cp -R 'dist/onboarding/KEEN Setup-darwin-universal/KEEN Setup.app' "$work/root/Applications/"
if [[ "$unsigned" != 1 ]]; then
 for binary in keen-posture keen-setup-helper; do
  codesign --force --options runtime --timestamp --sign "$APPLICATION_IDENTITY" "$work/root/usr/local/libexec/$binary"
  codesign --verify --strict --verbose=2 "$work/root/usr/local/libexec/$binary"
 done
 node onboarding/sign-mac.cjs "$work/root/Applications/KEEN Setup.app"
 codesign --verify --deep --strict --verbose=2 "$work/root/Applications/KEEN Setup.app"
else
 # Ad-hoc signatures permit local Apple Silicon testing; no distribution trust.
 for binary in keen-posture keen-setup-helper; do
  codesign --force --sign - "$work/root/usr/local/libexec/$binary"
 done
 codesign --force --deep --sign - --entitlements packaging/macos/setup-entitlements.plist "$work/root/Applications/KEEN Setup.app"
fi
cp packaging/macos/net.keen.posture.plist "$work/root/Library/LaunchDaemons/"
cp packaging/macos/postinstall "$work/scripts/postinstall"
chmod 755 "$work/scripts/postinstall"
chmod 644 "$work/root/Library/LaunchDaemons/net.keen.posture.plist"
pkgbuild --root "$work/root" --scripts "$work/scripts" --identifier net.keen.posture --version "$version" --install-location / "$work/unsigned.pkg"
if [[ "$unsigned" == 1 ]]; then
 cp "$work/unsigned.pkg" "$out/keen-posture-$version-macos-universal-unsigned.pkg"
 echo "$out/keen-posture-$version-macos-universal-unsigned.pkg"
 exit 0
fi
productsign --sign "$INSTALLER_IDENTITY" --timestamp "$work/unsigned.pkg" "$out/keen-posture-$version-macos-universal.pkg"
xcrun notarytool submit "$out/keen-posture-$version-macos-universal.pkg" --keychain-profile "$NOTARY_PROFILE" --wait --output-format json > "$work/notary.json"
[[ $(plutil -extract status raw -o - "$work/notary.json") == Accepted ]] || { cat "$work/notary.json"; exit 1; }
xcrun stapler staple "$out/keen-posture-$version-macos-universal.pkg"
xcrun stapler validate "$out/keen-posture-$version-macos-universal.pkg"
pkgutil --check-signature "$out/keen-posture-$version-macos-universal.pkg"
spctl --assess --type install --verbose=2 "$out/keen-posture-$version-macos-universal.pkg"
echo "$out/keen-posture-$version-macos-universal.pkg"
