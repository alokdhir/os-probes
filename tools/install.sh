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

# Install or update Probes on the OPNsense box itself, from a copy of this repository. Run as root:
#   sh tools/install.sh
# (tools/uninstall.sh removes it.)
#
# Files go where the package would put them (src/ -> /usr/local). The list of installed files is kept
# in /usr/local/etc/probes.files, so an update removes files that are gone from the new version.
# Health's cron job picks the graph up within a minute; configd is restarted for the widget's lists.

set -e

PREFIX=/usr/local
MANIFEST=$PREFIX/etc/probes.files
SRC=$(cd "$(dirname "$0")/../src" && pwd)

if [ "$(id -u)" != 0 ]; then
    echo "run as root (or with sudo)" >&2
    exit 1
fi
if [ ! -d "$PREFIX/opnsense/scripts/health/library/OPNsense/RRD" ]; then
    echo "this is not an OPNsense system with Health graphs" >&2
    exit 1
fi

NEW=$(mktemp)
(cd "$SRC" && find . -type f ! -name .DS_Store | sed 's#^\./##' | sort) > "$NEW"

# files from a previous version that this one no longer has
if [ -f "$MANIFEST" ]; then
    sort "$MANIFEST" | comm -23 - "$NEW" | while read -r f; do
        rm -f "$PREFIX/$f"
    done
fi

while read -r f; do
    mkdir -p "$PREFIX/$(dirname "$f")"
    install -o root -g wheel -m 644 "$SRC/$f" "$PREFIX/$f"
done < "$NEW"
install -o root -g wheel -m 644 "$NEW" "$MANIFEST"
rm -f "$NEW"
chmod 755 "$PREFIX/opnsense/scripts/probes/top.py"

# the ACL is cached, and configd reads its actions at start
rm -f /var/lib/php/tmp/opnsense_acl_cache.json
service configd restart >/dev/null

echo "Probes installed. The graph appears in Reporting -> Health within a minute or two."
