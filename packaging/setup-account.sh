#!/bin/sh
set -eu
getent group keen-agent >/dev/null || groupadd --system keen-agent
id keen-agent >/dev/null 2>&1 || useradd --system --gid keen-agent --home-dir /var/lib/keen-agent --shell /usr/sbin/nologin keen-agent
for group in systemd-journal adm www-data; do
 if getent group "$group" >/dev/null; then usermod -aG "$group" keen-agent; fi
done
install -d -o root -g keen-agent -m 0750 /etc/keen-agent
# Never replace an existing credential or operator configuration.
if [ ! -e /etc/keen-agent/token ]; then
 install -o root -g keen-agent -m 0640 /dev/null /etc/keen-agent/token
fi
if [ -f /etc/keen-agent/config.yaml ]; then
 chown root:keen-agent /etc/keen-agent/config.yaml
 chmod 0640 /etc/keen-agent/config.yaml
fi
install -d -o keen-agent -g keen-agent -m 0700 /var/lib/keen-agent
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
