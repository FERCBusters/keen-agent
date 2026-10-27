Name: keen-agent
Version: 0.1.10
Release: 1%{?dist}
Summary: KEEN evidence log collection agent
License: Apache-2.0
Requires: ca-certificates, systemd, shadow-utils
Requires(post): shadow-utils, systemd
Requires(preun): systemd
Requires(postun): systemd
%if 0%{?with_setup}
Requires: polkit, gtk3, nss, alsa-lib, libXScrnSaver, mesa-libgbm
%endif
%global debug_package %{nil}
%description
Durable OTLP/HTTP evidence collection with per-agent credentials.
%install
install -D -m 0755 %{_sourcedir}/keen-agent/dist/keen-setup-helper %{buildroot}%{_libexecdir}/keen-setup-helper
install -D -m 0644 %{_sourcedir}/keen-agent/packaging/keen-workstation.service %{buildroot}%{_unitdir}/keen-workstation.service
%if 0%{?with_setup}
mkdir -p %{buildroot}/opt/keen-setup
cp -a %{_sourcedir}/keen-agent/dist/setup-app/. %{buildroot}/opt/keen-setup/
chmod 4755 %{buildroot}/opt/keen-setup/chrome-sandbox
install -D -m 0644 %{_sourcedir}/keen-agent/packaging/keen-setup.desktop %{buildroot}%{_datadir}/applications/keen-setup.desktop
%endif
install -D -m 0755 %{_sourcedir}/keen-agent/dist/keen-agent %{buildroot}%{_bindir}/keen-agent
install -D -m 0640 %{_sourcedir}/keen-agent/examples/config.yaml %{buildroot}%{_sysconfdir}/keen-agent/config.yaml
install -D -m 0644 %{_sourcedir}/keen-agent/packaging/keen-agent.service %{buildroot}%{_unitdir}/keen-agent.service
sed -i 's|/usr/local/bin/keen-agent|/usr/bin/keen-agent|' %{buildroot}%{_unitdir}/keen-agent.service
install -D -m 0755 %{_sourcedir}/keen-agent/packaging/setup-account.sh %{buildroot}%{_libexecdir}/keen-agent/setup-account
mkdir -p %{buildroot}%{_docdir}/keen-agent
cp %{_sourcedir}/keen-agent/README.md %{_sourcedir}/keen-agent/LICENSE %{_sourcedir}/keen-agent/NOTICE %{buildroot}%{_docdir}/keen-agent/
cp -r %{_sourcedir}/keen-agent/licenses %{buildroot}%{_docdir}/keen-agent/
for unit in keen-posture-host.service keen-posture-host.timer; do
 install -D -m 0644 %{_sourcedir}/keen-agent/packaging/$unit %{buildroot}%{_unitdir}/$unit
done
for unit in keen-posture-session.service keen-posture-session.timer; do
 install -D -m 0644 %{_sourcedir}/keen-agent/packaging/$unit %{buildroot}%{_prefix}/lib/systemd/user/$unit
done
sed -i 's|/usr/local/bin/keen-agent|/usr/bin/keen-agent|' %{buildroot}%{_unitdir}/keen-posture-host.service %{buildroot}%{_prefix}/lib/systemd/user/keen-posture-session.service
install -D -m 0644 %{_sourcedir}/keen-agent/docs/posture-linux.md %{buildroot}%{_docdir}/keen-agent/posture.md
install -D -m 0644 %{_sourcedir}/keen-agent/examples/posture.yaml %{buildroot}%{_docdir}/keen-agent/examples/posture.yaml
install -D -m 0644 %{_sourcedir}/keen-agent/packaging/keen-posture-session.desktop %{buildroot}%{_docdir}/keen-agent/keen-posture-session.desktop
%post
%{_libexecdir}/keen-agent/setup-account
%preun
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
 systemctl disable --now keen-workstation.service keen-agent.service keen-posture-host.timer keen-posture-host.service || :
fi
%postun
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
%files
%{_libexecdir}/keen-setup-helper
%{_unitdir}/keen-workstation.service
%if 0%{?with_setup}
/opt/keen-setup
%{_datadir}/applications/keen-setup.desktop
%endif
%{_bindir}/keen-agent
%{_unitdir}/keen-agent.service
%{_unitdir}/keen-posture-host.service
%{_unitdir}/keen-posture-host.timer
%{_prefix}/lib/systemd/user/keen-posture-session.service
%{_prefix}/lib/systemd/user/keen-posture-session.timer
%{_libexecdir}/keen-agent
%dir %attr(0750,root,root) %{_sysconfdir}/keen-agent
%config(noreplace) %attr(0640,root,root) %{_sysconfdir}/keen-agent/config.yaml
%{_docdir}/keen-agent
