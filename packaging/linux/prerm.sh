#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Debian pre-removal hook for tpt-netguard. When the package is removed or purged, delete the
# nftables table that holds the block-all ("panic button") ruleset, so uninstalling can never
# leave the machine without internet. The table name must match `TABLE` in
# platform-linux/src/nft.rs; a test there checks that. Per-app eBPF programs are attached to
# cgroups by the running process and go away with it, so they need nothing here.
#
# Upgrades are left alone: the new version re-applies the saved block-all setting on start.

set -e

case "$1" in
    remove|purge)
        if command -v nft >/dev/null 2>&1; then
            nft delete table inet tpt_netguard 2>/dev/null || true
        fi
        ;;
esac

exit 0
