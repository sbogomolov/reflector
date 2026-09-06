#!/usr/bin/env bash
# Exercise the installed plugin on the converted OPNsense VM (ci/freebsd-vm.sh
# env applies), the way a user's firewall runs it: the model checked against
# this core, the configuration rendered by real configd, validated by the
# daemon and through the GUI's own check action, the service started. No sysrc:
# the seeded config.xml arms the
# service through the plugin's rc.conf.d template, the same path a user's
# firewall takes (and /etc/rc.conf.d overrides rc.conf anyway).
set -euo pipefail

HERE="$(dirname "$0")"

"$HERE"/freebsd-vm.sh push "$HERE"/modelcheck.php /tmp/modelcheck.php
"$HERE"/freebsd-vm.sh run 'php /tmp/modelcheck.php'
"$HERE"/freebsd-vm.sh run 'configctl template reload OPNsense/Netflector'
"$HERE"/freebsd-vm.sh run 'test -s /usr/local/etc/netflector.toml'
"$HERE"/freebsd-vm.sh run 'cat /usr/local/etc/netflector.toml'
"$HERE"/freebsd-vm.sh run 'netflector --check-config /usr/local/etc/netflector.toml'
# The gate config spells its MACs in hyphen and dot form; the template must fold both.
"$HERE"/freebsd-vm.sh run 'grep -q "^macs = \[\"b0:37:95:c5:60:be\", \"c4:9d:8f:11:22:33\"\]$" /usr/local/etc/netflector.toml'

# restart, not start: freebsd-vm.sh wait only waits for sshd, so the plugin can be installed while
# the boot is still running. Whether the boot reaches its service phase before or after the plugin
# writes rc.conf.d decides whether the daemon is already up by now, and start fails when it is.
"$HERE"/freebsd-vm.sh run 'service netflector restart && sleep 2 && service netflector status'
