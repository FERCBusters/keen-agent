# Releasing KEEN Agent

One release produces, from one version number:

| Artefact | Built on | By | Published to |
| --- | --- | --- | --- |
| `keen-agent` DEB for Debian 12 and 13 | Linux with Docker | `packaging/release-linux.sh` | the APT repository (`apt.mig5.net`) |
| `keen-agent` RPM for Fedora 43 and 44 | Linux with Docker | `packaging/release-linux.sh` | the RPM repository (`rpm.mig5.net`) |
| `keen-posture-<version>-windows-amd64.msi` and `-arm64.msi` | Windows | `packaging/windows/build-sign.ps1` | the download area |
| `keen-posture-<version>-macos-universal.pkg` | macOS | `packaging/macos/build-sign-notarize.sh` | the download area |

The download area is `https://keen.cloud/downloads/keen-agent/<version>/`, with
`https://keen.cloud/downloads/keen-agent/latest/` pointing at the newest
release. Every file there has a detached OpenPGP signature (`.asc`) made with
the release key, and `SHA256SUMS` lists every file's SHA-256 and is itself
signed. Windows and macOS installers are additionally signed with their
platforms' code-signing identities. The keen.cloud `/agent` page links to the
download area and explains how to verify downloads.

The release key is `54A9 1143 AE0A B4F7 743B  01FE 888E D1B4 23A3 BC99`,
published at `https://mig5.net/static/mig5.asc`. It signs the APT and RPM
repository metadata, the packages and every download.

## The version

`VERSION` at the repository root is the release version. Three other files
record it, and a test fails if any of them differs:

- `internal/buildinfo/buildinfo.go` (the version every binary reports and
  sends as `application_version` in its evidence);
- `onboarding/package.json` and `onboarding/package-lock.json` (the setup app).

The packaging scripts read `VERSION` directly: the RPM spec through
`--define agent_version`, the DEB control file, the WiX product version and
installer name, and the macOS package version and name.

Change all of them with:

```sh
scripts/set-version.sh 0.2.1
```

A version changes only for a release. Work between releases keeps the version
of the release it leads to; it is not bumped per change, and the repository
keeps no changelog files. Release notes are written once, in the Git tag
message and the release announcement.

## 1. Prepare

On a clean checkout of the commit to release:

```sh
scripts/set-version.sh 0.2.0      # only if VERSION is not already right
make test                          # Go race tests and vet
npm ci --prefix onboarding && npm test --prefix onboarding
git commit -am "Release 0.2.0"     # when set-version changed anything
git tag -s v0.2.0 -m "KEEN Agent 0.2.0"
```

Check the evidence profile's golden vectors are current: `go test
./internal/ueu` compares the envelope, manifest and request signature bytes
with `internal/ueu/testdata/vectors.json`. If the protocol changed
deliberately, regenerate them with `UPDATE_VECTORS=1 go test ./internal/ueu
-run TestVectors` and copy the file to KEEN's
`services/api/tests/fixtures/ueu-vectors.json` in the same release.

## 2. Linux packages and repositories

On the Linux release host (Docker, `reprepro`, `rpmsign`, `createrepo_c`,
`rpm` and the signing command installed):

```sh
bash release.sh            # servers: keen-agent without the setup app
bash release.sh --sync     # and copy the RPM repository to its host
```

`release.sh` is the local, untracked wrapper holding mig5's repository paths
and key; it runs `packaging/release-linux.sh`, which:

1. checks the version files agree;
2. builds every target in Docker in a fresh staging directory, running the Go
   tests inside each build;
3. refuses to publish unless each target produced exactly one package of
   `VERSION`;
4. signs each DEB (detached `.asc`) and adds it to its suite with `reprepro`;
5. signs each RPM, copies it into `<release>/rpm/<arch>/`, rebuilds the
   repository metadata and signs `repomd.xml`;
6. copies the signed packages to `dist/packages/<target>/`.

A copy of `release.sh`:

```bash
#!/bin/bash
# mig5's release settings for packaging/release-linux.sh. Kept out of Git.
#   bash release.sh [--with-setup] [--sync]
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
export SIGNING_KEY=${SIGNING_KEY:-54A91143AE0AB4F7743B01FE888ED1B423A3BC99}
export GPG=${GPG:-qubes-gpg-client}
export DEB_REPO=${DEB_REPO:-/home/user/git/repo}
export RPM_REPO_ROOT=${RPM_REPO_ROOT:-${HOME}/git/repo_rpm}
export RPM_REMOTE=${RPM_REMOTE:-ashpool.mig5.net:/opt/repo_rpm}
exec packaging/release-linux.sh "$@"
```

`--with-setup` adds the KEEN Setup desktop app to the Linux packages, for Linux
workstations. It needs Node.js 22.12+ and npm on the release host and makes
the package depend on GTK, NSS and Polkit, so publish it only where those are
wanted; servers use the default. To build packages without publishing, use
`sh packaging/build-packages.sh debian13 fedora44` (output in
`dist/packages/`), or `sh packaging/build-workstation.sh debian13` to include
the setup app.

## 3. Windows installers

On Windows with Go (the version in `go.mod`), Node.js 22.12+, npm, WiX 4+ and
the Windows SDK `signtool`, with the code-signing token's middleware installed:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\packaging\windows\build-sign.ps1 -Architecture amd64 -CertificateThumbprint THUMBPRINT -TimestampUrl https://TSA
.\packaging\windows\build-sign.ps1 -Architecture arm64 -CertificateThumbprint THUMBPRINT -TimestampUrl https://TSA
```

Each run builds and signs `keen-posture.exe`, `keen-setup-helper.exe` and the
setup app's executables, builds the MSI, signs it and verifies every
signature. Output: `dist\windows-<arch>\keen-posture-<version>-windows-<arch>.msi`.
The hardware token prompts for its PIN; no key or PIN is an argument.
`-Unsigned` builds a test MSI without Authenticode signatures.

Copy both MSIs to the Linux release host's `dist/windows-amd64/` and
`dist/windows-arm64/`.

## 4. macOS package

On macOS with Go, Node.js 22.12+, npm, the Xcode command-line tools and the
Developer ID identities in the keychain:

```sh
export APPLICATION_IDENTITY='Developer ID Application: NAME (TEAMID)'
export INSTALLER_IDENTITY='Developer ID Installer: NAME (TEAMID)'
export NOTARY_PROFILE='keen-notary'
./packaging/macos/build-sign-notarize.sh
```

This builds universal Intel and Apple Silicon binaries and the setup app, signs
them with the hardened runtime, builds and signs the package, notarises and
staples it, and checks it with `spctl`. Output:
`dist/macos/keen-posture-<version>-macos-universal.pkg`. `UNSIGNED=1` builds an
ad hoc signed test package instead.

Copy the package to the Linux release host's `dist/macos/`.

## 5. Stage and publish the downloads

On the Linux release host, with the Windows and macOS installers copied into
`dist/` and the Linux packages from step 2 still in `dist/packages/`:

```sh
GPG=qubes-gpg-client SIGNING_KEY=54A91143AE0AB4F7743B01FE888ED1B423A3BC99 \
  packaging/stage-downloads.sh
rsync -aHv dist/downloads/keen-agent/ keen.cloud:/srv/keen-cloud/downloads/keen-agent/
```

`stage-downloads.sh` copies every artefact whose name carries `VERSION` into
`dist/downloads/keen-agent/<version>/`, writes `SHA256SUMS`, signs each file
and the sums, and points `latest` at the new version. It refuses an artefact
named for another version. Pass artefact paths as arguments to stage a subset.

keen.cloud serves `/srv/keen-cloud/downloads` at `/downloads/` (see the
portal's `deploy/control/Caddyfile.example`). Set `CLOUD_AGENT_VERSION` in the
portal's environment to the new version and restart it, so the `/agent` page
links to the new files.

## 6. Check the release

From a machine that is not the build host:

```sh
curl -fsSLO https://mig5.net/static/mig5.asc && gpg --import mig5.asc
gpg --fingerprint 54A91143AE0AB4F7743B01FE888ED1B423A3BC99
base=https://keen.cloud/downloads/keen-agent/0.2.0
curl -fsSLO $base/SHA256SUMS -fsSLO $base/SHA256SUMS.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
curl -fsSLO $base/keen-posture-0.2.0-macos-universal.pkg
sha256sum --check --ignore-missing SHA256SUMS
```

Then install from the repositories on a fresh Debian and Fedora host
(`apt install keen-agent`, `dnf install keen-agent`), confirm `keen-agent
-command version` prints the release version, enrol one server and one
workstation of each platform against a test KEEN and check their evidence
shows **Signature verified** and a continuous chain.

## Files involved

| File | Purpose |
| --- | --- |
| `VERSION` | the release version |
| `scripts/set-version.sh` | sets the version everywhere and checks it |
| `internal/buildinfo/` | the version in Go, and the test that keeps copies equal |
| `packaging/release-linux.sh` | builds, signs and publishes Linux packages |
| `packaging/build-packages.sh` | builds Linux packages in Docker (no publishing) |
| `packaging/build-workstation.sh` | the same, with the setup app |
| `packaging/Dockerfile.debian`, `Dockerfile.fedora`, `build-deb.sh`, `keen-agent.spec` | package definitions |
| `packaging/windows/build-sign.ps1`, `Product.wxs` | the Windows installer |
| `packaging/macos/build-sign-notarize.sh` | the macOS package |
| `packaging/stage-downloads.sh` | the signed download layout |
| `release.sh` (untracked) | local repository paths and key for `release-linux.sh` |
