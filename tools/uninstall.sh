#!/bin/sh
# Copyright (C) 2026 Alok K. Dhir
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# Remove Probes from the OPNsense box. Run as root:
#   sh tools/uninstall.sh
# Removes the files listed in /usr/local/etc/probes.files (written by install.sh). The collected totals
# (/var/db/probes/) are kept; delete that directory to remove them too.

set -e

PREFIX=/usr/local
MANIFEST=$PREFIX/etc/probes.files

if [ "$(id -u)" != 0 ]; then
    echo "run as root (or with sudo)" >&2
    exit 1
fi
if [ ! -f "$MANIFEST" ]; then
    echo "Probes is not installed (no $MANIFEST)" >&2
    exit 1
fi

while read -r f; do
    rm -f "$PREFIX/$f"
done < "$MANIFEST"
rm -f "$MANIFEST"
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json
service configd restart >/dev/null
for i in 1 2 3 4 5 6 7 8 9 10; do        # configd takes a moment to come back
    configctl cron restart >/dev/null 2>&1 && break
    sleep 1
done

echo "Probes removed. Its totals are still in /var/db/probes/; delete that directory to remove them."
