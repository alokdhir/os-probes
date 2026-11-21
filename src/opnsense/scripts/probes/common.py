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

import ipaddress
import os
import sqlite3
import xml.etree.ElementTree as ET

CONFIG = '/conf/config.xml'
DB = '/var/db/probes/probes.db'
DAYS = 30                       # how long the hourly totals are kept
PERIODS = (1, 3, 24, 168, 720)  # the page's periods (hours): their totals are kept ready, see collect.rollup()
RECENT = 3                      # hours kept per 5 minutes too, for the short periods
REPLY_WINDOW = 3600             # a packet from an address your network contacted this recently is a late reply
VERSION = '3'                   # the tables' layout: another one starts the database over (the log is read again)

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
-- the same per 5 minutes ("hour" is the start of the 5 minutes), for the last RECENT hours
CREATE TABLE IF NOT EXISTS hits5 (
    hour INTEGER, ip TEXT, proto TEXT, port INTEGER, packets INTEGER, listed INTEGER,
    PRIMARY KEY (hour, ip, proto, port)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS hits5_ip ON hits5 (ip, hour);
-- the same packets per minute, for the graph; replies: blocked packets that were late replies (not in hits)
CREATE TABLE IF NOT EXISTS totals (t INTEGER PRIMARY KEY, packets INTEGER, listed INTEGER, replies INTEGER);
-- addresses your network connected to (outbound passes in the log, and the firewall's states), and when last
-- which blocklist rules blocked a source (the rule's description, else its alias), and when last
CREATE TABLE IF NOT EXISTS listed_by (ip TEXT, list TEXT, last INTEGER, PRIMARY KEY (ip, list)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS contacts (ip TEXT PRIMARY KEY, last INTEGER) WITHOUT ROWID;
-- blocked packets from those addresses soon after (see REPLY_WINDOW): replies to a connection that already
-- closed, or a peer-to-peer VPN trying ports, not probes; per hour, source and port
CREATE TABLE IF NOT EXISTS replies (
    hour INTEGER, ip TEXT, proto TEXT, port INTEGER, packets INTEGER,
    PRIMARY KEY (hour, ip, proto, port)
) WITHOUT ROWID;
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
    """ where a period starts: in whole hours (the current one and the ones before it), or for the short periods
        in 5 minutes (the current 5 minutes and the ones before it) """
    if int(hours) <= RECENT:
        return now - now % 300 - int(hours) * 3600 + 300
    return now - now % 3600 - (int(hours) - 1) * 3600


def hits_table(hours):
    """ the rows a period is added up from """
    return 'hits5' if int(hours) <= RECENT else 'hits'


def connect(readonly=False):
    if readonly:
        if not os.path.exists(DB):
            return None
        return sqlite3.connect('file:%s?mode=ro' % DB, uri=True, timeout=10)
    os.makedirs(os.path.dirname(DB), mode=0o750, exist_ok=True)
    db = sqlite3.connect(DB, timeout=30)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)')
    version = db.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()
    if not version or version[0] != VERSION:
        # an older layout: start over, keeping the GeoIP lists, and read the log again
        with db:
            for (table,) in db.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT IN "
                                       "('meta', 'geo4', 'geo6')").fetchall():
                db.execute('DROP TABLE %s' % table)
            db.execute("DELETE FROM meta WHERE key NOT IN ('geo')")
            db.execute("INSERT INTO meta (key, value) VALUES ('version', ?)", (VERSION,))
    db.executescript(SCHEMA)
    return db


def country(db, ip):
    """ the country of an address from the GeoIP lists: ISO code, or '' when unknown """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ''
    if addr.version == 4:
        row = db.execute('SELECT end, cc FROM geo4 WHERE start <= ? ORDER BY start DESC LIMIT 1',
                         (int(addr),)).fetchone()
        return row[1] if row and int(addr) <= row[0] else ''
    row = db.execute('SELECT end, cc FROM geo6 WHERE start <= ? ORDER BY start DESC LIMIT 1',
                     (addr.packed,)).fetchone()
    return row[1] if row and addr.packed <= row[0] else ''


def text(node, path):
    found = node.find(path)
    return (found.text or '').strip() if found is not None else ''


def wan_interfaces(root=None):
    """ {interface name (wan, opt1...): device (igb0...)}: enabled, with a gateway or an address from the provider,
        or with an upstream gateway in System > Gateways (a static WAN can have its gateway only there) """
    root = root if root is not None else ET.parse(CONFIG).getroot()
    upstream = {
        text(gw, 'interface') for gw in root.iterfind('OPNsense/Gateways/gateway_item')
        if text(gw, 'defaultgw') == '1' and text(gw, 'disabled') != '1'
    }
    wans = {}
    interfaces = root.find('interfaces')
    for node in (interfaces if interfaces is not None else []):
        if node.find('enable') is None or not text(node, 'if'):
            continue
        if text(node, 'gateway') or text(node, 'gatewayv6') or node.tag in upstream or \
                text(node, 'ipaddr') in DYNAMIC or text(node, 'ipaddrv6') in DYNAMIC:
            wans[node.tag] = text(node, 'if')
    return wans


def read_config():
    """ :return: (WAN devices, {uuid: name} of the blocklist rules on them) """
    root = ET.parse(CONFIG).getroot()
    wans = wan_interfaces(root)

    lists = {
        text(alias, 'name') for alias in root.iterfind('OPNsense/Firewall/Alias/aliases/alias')
        if text(alias, 'enabled') == '1' and text(alias, 'type') in LIST_TYPES
    }
    rules = {}
    for rule in root.iterfind('OPNsense/Firewall/Filter/rules/rule'):
        if text(rule, 'enabled') != '1' or text(rule, 'action') not in ('block', 'reject') or \
                text(rule, 'direction') == 'out' or text(rule, 'source_not') == '1':
            continue
        sources = lists.intersection(filter(None, text(rule, 'source_net').split(',')))
        if not sources:
            continue
        listed = set(filter(None, text(rule, 'interface').split(',')))
        invert = text(rule, 'interfacenot') == '1'
        if not listed or any((ifname in listed) != invert for ifname in wans):
            rules[rule.get('uuid', '').lower()] = text(rule, 'description') or ', '.join(sorted(sources))
    return set(wans.values()), rules
