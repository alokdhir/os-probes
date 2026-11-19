#!/usr/local/bin/python3

"""
    Copyright (C) 2026 Alok K. Dhir
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

    --------------------------------------------------------------------------------------
    The last 24 hours of the firewall log, summed up: the ports and the sources with the most packets blocked
    coming in on a WAN. Only rules that log are in the log (the default deny rule does, unless that is turned off),
    so these are a share of the graph's "all" line.

    Usage: top.py [count]     JSON on stdout
"""

import collections
import datetime
import glob
import json
import socket
import sys
import xml.etree.ElementTree as ET

CONFIG = '/conf/config.xml'
LOGS = '/var/log/filter/filter_*.log'
HOURS = 24

# the same tests as the Health collector (Stats/Attacks.php)
LIST_TYPES = {'url', 'urltable', 'urljson'}
DYNAMIC = {'dhcp', 'dhcp6', 'pppoe', 'pptp', 'l2tp', 'slaac', '6rd', '6to4'}

# filterlog's CSV layout (core's scripts/filter/read_log.py): where protocol, addresses and ports are
FIELDS = {'4': (16, 18, 20, 21), '6': (12, 15, 17, 18)}   # protoname, src, srcport, dstport


def text(node, path):
    found = node.find(path)
    return (found.text or '').strip() if found is not None else ''


def read_config():
    """ :return: (WAN devices, uuids of the blocklist rules on them) """
    root = ET.parse(CONFIG).getroot()
    wans = {}
    interfaces = root.find('interfaces')
    for node in (interfaces if interfaces is not None else []):
        if node.find('enable') is None or not text(node, 'if'):
            continue
        if text(node, 'gateway') or text(node, 'gatewayv6') or \
                text(node, 'ipaddr') in DYNAMIC or text(node, 'ipaddrv6') in DYNAMIC:
            wans[node.tag] = text(node, 'if')

    lists = {
        text(alias, 'name') for alias in root.iterfind('OPNsense/Firewall/Alias/aliases/alias')
        if text(alias, 'enabled') == '1' and text(alias, 'type') in LIST_TYPES
    }
    rules = set()
    for rule in root.iterfind('OPNsense/Firewall/Filter/rules/rule'):
        if text(rule, 'enabled') != '1' or text(rule, 'action') not in ('block', 'reject') or \
                text(rule, 'direction') == 'out' or text(rule, 'source_not') == '1':
            continue
        if not lists.intersection(filter(None, text(rule, 'source_net').split(','))):
            continue
        listed = set(filter(None, text(rule, 'interface').split(',')))
        invert = text(rule, 'interfacenot') == '1'
        if not listed or any((ifname in listed) != invert for ifname in wans):
            rules.add(rule.get('uuid', '').lower())
    return set(wans.values()), rules


def service(proto, port):
    try:
        return socket.getservbyport(int(port), proto)
    except (OSError, ValueError, OverflowError):
        return ''


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 5
    devices, blocklist_rules = read_config()
    # the log's timestamps are local time with an offset (2026-11-19T14:02:03-05:00): comparing the first 19
    # characters as text is enough, and much quicker than parsing every one
    cutoff = (datetime.datetime.now() - datetime.timedelta(hours=HOURS)).strftime('%Y-%m-%dT%H:%M:%S')

    ports = collections.Counter()
    port_sources = collections.defaultdict(set)
    sources = collections.Counter()
    source_ports = collections.defaultdict(collections.Counter)
    listed = set()
    first = None
    total = 0

    # a file a day, named by date: the last two cover any 24 hours
    for path in sorted(glob.glob(LOGS))[-2:]:
        try:
            log = open(path, 'rb')
        except OSError:
            continue
        with log:
            for raw in log:
                # most of the log is usually passes: skip them before decoding or parsing anything
                if b',block,in,' not in raw or b'filterlog' not in raw:
                    continue
                line = raw.decode('utf-8', 'replace')
                # RFC 5424: <pri>1 timestamp host filterlog pid - [meta] csv
                parts = line.split()
                if len(parts) < 3:
                    continue
                f = parts[-1].split(',')
                if len(f) < 9 or f[6] != 'block' or f[7] != 'in' or f[4] not in devices or f[8] not in FIELDS:
                    continue
                when = parts[1][:19]
                if when < cutoff:
                    continue
                p_proto, p_src, _, p_dport = FIELDS[f[8]]
                if len(f) <= p_src:
                    continue
                proto, src = f[p_proto], f[p_src]
                port = f[p_dport] if proto in ('tcp', 'udp') and len(f) > p_dport else ''
                key = (proto, port)
                total += 1
                if first is None or when < first:
                    first = when
                ports[key] += 1
                port_sources[key].add(src)
                sources[src] += 1
                source_ports[src][key] += 1
                if f[3].lower() in blocklist_rules:
                    listed.add(src)

    print(json.dumps({
        'hours': HOURS,
        'logged': total,
        'since': int(datetime.datetime.strptime(first, '%Y-%m-%dT%H:%M:%S').timestamp()) if first else None,
        'ports': [
            {'proto': proto, 'port': port, 'service': service(proto, port) if port else '',
             'packets': n, 'sources': len(port_sources[(proto, port)])}
            for (proto, port), n in ports.most_common(count)
        ],
        'sources': [
            {'ip': src, 'packets': n, 'ports': len(source_ports[src]), 'blocklist': src in listed,
             'top': [{'proto': p, 'port': q} for (p, q), _ in source_ports[src].most_common(1)][0]}
            for src, n in sources.most_common(count)
        ]
    }))


if __name__ == '__main__':
    main()
