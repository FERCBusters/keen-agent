Name: keen-agent
Version: 0.1.6
Release: 1%{?dist}
Summary: KEEN evidence log collection agent
License: Apache-2.0
Requires: ca-certificates, systemd, shadow-utils
Requires(post): shadow-utils, systemd
Requires(preun): systemd
Requires(postun): systemd
%global debug_package %{nil}
%description
Durable OTLP/HTTP evidence collection with per-agent credentials.
%install
install -D -m 0755 %{_sourcedir}/keen-agent/dist/keen-agent %{buildroot}%{_bindir}/keen-agent
install -D -m 0640 %{_sourcedir}/keen-agent/examples/config.yaml %{buildroot}%{_sysconfdir}/keen-agent/config.yaml
install -D -m 0644 %{_sourcedir}/keen-agent/packaging/keen-agent.service %{buildroot}%{_unitdir}/keen-agent.service
sed -i 's|/usr/local/bin/keen-agent|/usr/bin/keen-agent|' %{buildroot}%{_unitdir}/keen-agent.service
install -D -m 0755 %{_sourcedir}/keen-agent/packaging/setup-account.sh %{buildroot}%{_libexecdir}/keen-agent/setup-account
mkdir -p %{buildroot}%{_docdir}/keen-agent
cp %{_sourcedir}/keen-agent/README.md %{_sourcedir}/keen-agent/LICENSE %{_sourcedir}/keen-agent/NOTICE %{buildroot}%{_docdir}/keen-agent/
cp -r %{_sourcedir}/keen-agent/licenses %{buildroot}%{_docdir}/keen-agent/
%post
%{_libexecdir}/keen-agent/setup-account
%preun
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
 systemctl disable --now keen-agent.service || :
fi
%postun
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
%files
%{_bindir}/keen-agent
%{_unitdir}/keen-agent.service
%{_libexecdir}/keen-agent
%dir %attr(0750,root,root) %{_sysconfdir}/keen-agent
%config(noreplace) %attr(0640,root,root) %{_sysconfdir}/keen-agent/config.yaml
%{_docdir}/keen-agent
