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
    What the collector and the queries share: the database, and which interfaces and rules count.
"""

import os
import sqlite3
import xml.etree.ElementTree as ET

CONFIG = '/conf/config.xml'
DB = '/var/db/probes/probes.db'
DAYS = 30                       # how long the hourly totals are kept
PERIODS = (24, 168, 720)        # the page's periods (hours): their totals are kept ready, see collect.rollup()

# the same tests as the Health collector (Stats/Probes.php)
LIST_TYPES = {'url', 'urltable', 'urljson'}
DYNAMIC = {'dhcp', 'dhcp6', 'pppoe', 'pptp', 'l2tp', 'slaac', '6rd', '6to4'}

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
-- packets blocked coming in on a WAN, per hour, source and destination port (-1: a protocol without ports);
-- listed: how many of them a blocklist rule blocked
CREATE TABLE IF NOT EXISTS hits (
    hour INTEGER, ip TEXT, proto TEXT, port INTEGER, packets INTEGER, listed INTEGER,
    PRIMARY KEY (hour, ip, proto, port)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS hits_ip ON hits (ip, hour);
-- the same packets per 5 minutes, for the graph
CREATE TABLE IF NOT EXISTS totals (t INTEGER PRIMARY KEY, packets INTEGER, listed INTEGER);
-- country: ISO code, '' when looked up and unknown, NULL when not looked up yet
CREATE TABLE IF NOT EXISTS sources (ip TEXT PRIMARY KEY, country TEXT, first INTEGER, last INTEGER) WITHOUT ROWID;
-- per period, the totals the page shows, rebuilt every few minutes (a scanner sends a packet or two per port, so
-- adding up the hourly rows for 30 days takes seconds)
CREATE TABLE IF NOT EXISTS agg_meta (period INTEGER PRIMARY KEY, built INTEGER, since INTEGER, packets INTEGER,
    listed INTEGER, sources INTEGER);
CREATE TABLE IF NOT EXISTS agg_sources (period INTEGER, ip TEXT, country TEXT, packets INTEGER, ports INTEGER,
    listed INTEGER, first INTEGER, last INTEGER, top_proto TEXT, top_port INTEGER, PRIMARY KEY (period, ip)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS agg_sources_packets ON agg_sources (period, packets);
CREATE TABLE IF NOT EXISTS agg_ports (period INTEGER, proto TEXT, port INTEGER, packets INTEGER, sources INTEGER,
    PRIMARY KEY (period, proto, port)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS agg_countries (period INTEGER, country TEXT, packets INTEGER, sources INTEGER,
    PRIMARY KEY (period, country)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS geo4 (start INTEGER PRIMARY KEY, end INTEGER, cc TEXT);
CREATE TABLE IF NOT EXISTS geo6 (start BLOB PRIMARY KEY, end BLOB, cc TEXT) WITHOUT ROWID;
"""


def period_start(hours, now):
    """ the first hour of a period: the current hour plus the ones before it """
    return now - now % 3600 - (int(hours) - 1) * 3600


def connect(readonly=False):
    if readonly:
        if not os.path.exists(DB):
            return None
        return sqlite3.connect('file:%s?mode=ro' % DB, uri=True, timeout=10)
    os.makedirs(os.path.dirname(DB), mode=0o750, exist_ok=True)
    db = sqlite3.connect(DB, timeout=30)
    db.execute('PRAGMA journal_mode=WAL')
    db.executescript(SCHEMA)
    return db


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
