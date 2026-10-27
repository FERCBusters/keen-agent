#!/bin/sh
# Build on Linux for the host architecture, then use the existing native builders.
set -eu
cd "$(dirname "$0")/.."
case "$(uname -m)" in x86_64) arch=x64;; aarch64|arm64) arch=arm64;; *) echo 'Unsupported architecture' >&2; exit 1;; esac
npm ci --prefix onboarding
npm test --prefix onboarding
SETUP_PLATFORM=linux SETUP_ARCH="$arch" npm run package --prefix onboarding
rm -rf dist/setup-app
cp -a "dist/onboarding/KEEN Setup-linux-$arch" dist/setup-app
cp dist/setup-icons/keen.png dist/setup-app/keen.png
exec ./packaging/build-packages.sh "$@"
