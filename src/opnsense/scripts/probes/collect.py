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
    Runs every minute (cron, from plugins.inc.d/probes.inc): reads the firewall log lines written since the
    last run and adds the packets blocked coming in on a WAN to hourly totals per source and port. The first
    run reads the last DAYS days. Also keeps a country per source, from the GeoIP data OPNsense downloads
    for GeoIP aliases (Firewall > Aliases > GeoIP settings), when that is set up.
"""

import collections
import datetime
import fcntl
import glob
import ipaddress
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import connect, read_config, country, period_start, hits_table, DAYS, PERIODS, RECENT, \
    REPLY_WINDOW  # noqa: E402

LOGS = '/var/log/filter/filter_*.log'
LOCK = '/var/run/probes.lock'
GEO_DIR = '/usr/local/share/GeoIP/alias'
GEO_STATS = '/usr/local/share/GeoIP/alias.stats'

# filterlog's CSV layout (core's scripts/filter/read_log.py): where protocol, source, destination and its port are
FIELDS = {'4': (16, 18, 19, 21), '6': (12, 15, 16, 18)}


def read_logs(db, devices, blocklist_rules, cutoff):
    """ add the log lines since the last run; :return: number of blocked packets added """
    meta = dict(db.execute("SELECT key, value FROM meta WHERE key IN ('file', 'offset')"))
    files = sorted(glob.glob(LOGS))
    last_file, offset = meta.get('file'), int(meta.get('offset', 0))
    if last_file in files:
        files = files[files.index(last_file):]
    else:
        # first run, or the file we were in is gone: start at the files that can hold the last DAYS days
        first_day = (datetime.date.today() - datetime.timedelta(days=DAYS)).strftime('filter_%Y%m%d.log')
        files = [f for f in files if os.path.basename(f) >= first_day]
        last_file, offset = None, 0

    recent = int(time.time()) - RECENT * 3600 - 300
    contacted = Contacts(db)
    added = 0
    for path in files:
        # one file (a day) at a time, saved as it's done: an interrupted first run picks up where it stopped
        added += read_file(db, path, offset if path == last_file else 0, devices, blocklist_rules, cutoff, recent,
                           contacted)
    with db:
        db.execute('DELETE FROM hits5 WHERE hour < ?', (recent - recent % 300,))
    return added


class Contacts:
    """ when your network last connected to an address: what the log has said so far, else the database """
    def __init__(self, db):
        self.db = db
        self.known = {}
        self.fresh = set()

    def saw(self, ip, when):
        self.known[ip] = when
        self.fresh.add(ip)

    def last(self, ip):
        if ip not in self.known:
            row = self.db.execute('SELECT last FROM contacts WHERE ip = ?', (ip,)).fetchone()
            self.known[ip] = row[0] if row else None
        return self.known[ip]

    def save(self):
        self.db.executemany('INSERT INTO contacts (ip, last) VALUES (?, ?) '
                            'ON CONFLICT (ip) DO UPDATE SET last = max(last, excluded.last)',
                            [(ip, self.known[ip]) for ip in self.fresh])
        self.fresh.clear()


def read_file(db, path, start, devices, blocklist_rules, cutoff, recent, contacted):
    hits = collections.Counter()
    replies = collections.Counter()
    totals_replies = collections.Counter()
    listed = collections.Counter()
    totals = collections.Counter()
    totals_listed = collections.Counter()
    hits5 = collections.Counter()
    listed5 = collections.Counter()
    seen = {}
    try:
        log = open(path, 'rb')
    except OSError:
        return 0
    with log:
        if start > os.fstat(log.fileno()).st_size:
            start = 0                           # the file was replaced
        log.seek(start)
        pos = start
        for raw in log:
            if not raw.endswith(b'\n'):
                break                           # still being written: next run
            pos += len(raw)
            # blocks coming in, and connections going out (to tell late replies from probes); skip the rest
            # before decoding or parsing anything
            outbound = b',pass,out,' in raw
            if not outbound and b',block,in,' not in raw or b'filterlog' not in raw:
                continue
            parts = raw.decode('utf-8', 'replace').split()
            if len(parts) < 3:
                continue
            f = parts[-1].split(',')
            if len(f) < 9 or f[4] not in devices or f[8] not in FIELDS or \
                    (f[6], f[7]) != (('pass', 'out') if outbound else ('block', 'in')):
                continue
            try:
                when = int(datetime.datetime.fromisoformat(parts[1]).timestamp())
            except ValueError:
                continue
            p_proto, p_src, p_dst, p_dport = FIELDS[f[8]]
            if len(f) <= p_dst:
                continue
            if outbound:
                contacted.saw(f[p_dst], when)
                continue
            if when < cutoff:
                continue
            proto, src = f[p_proto], f[p_src]
            port = int(f[p_dport]) if proto in ('tcp', 'udp') and len(f) > p_dport and f[p_dport].isdigit() else -1
            key = (when - when % 3600, src, proto, port)
            key5 = (when - when % 300, src, proto, port)
            is_listed = f[3].lower() in blocklist_rules
            last_contact = contacted.last(src)
            if not is_listed and last_contact is not None and last_contact >= when - REPLY_WINDOW:
                replies[key] += 1
                totals_replies[when - when % 60] += 1
                continue
            hits[key] += 1
            totals[when - when % 60] += 1
            if when >= recent:
                hits5[key5] += 1
            if is_listed:
                listed[key] += 1
                totals_listed[when - when % 60] += 1
                if when >= recent:
                    listed5[key5] += 1
            first, last = seen.get(src, (when, when))
            seen[src] = (min(first, when), max(last, when))

    with db:
        db.executemany(
            'INSERT INTO hits (hour, ip, proto, port, packets, listed) VALUES (?, ?, ?, ?, ?, ?) '
            'ON CONFLICT (hour, ip, proto, port) DO UPDATE SET '
            'packets = packets + excluded.packets, listed = listed + excluded.listed',
            [(*key, n, listed[key]) for key, n in hits.items()])
        db.executemany(
            'INSERT INTO hits5 (hour, ip, proto, port, packets, listed) VALUES (?, ?, ?, ?, ?, ?) '
            'ON CONFLICT (hour, ip, proto, port) DO UPDATE SET '
            'packets = packets + excluded.packets, listed = listed + excluded.listed',
            [(*key, n, listed5[key]) for key, n in hits5.items()])
        db.executemany(
            'INSERT INTO replies (hour, ip, proto, port, packets) VALUES (?, ?, ?, ?, ?) '
            'ON CONFLICT (hour, ip, proto, port) DO UPDATE SET packets = packets + excluded.packets',
            [(*key, n) for key, n in replies.items()])
        db.executemany(
            'INSERT INTO totals (t, packets, listed, replies) VALUES (?, ?, ?, ?) '
            'ON CONFLICT (t) DO UPDATE SET packets = packets + excluded.packets, listed = listed + excluded.listed, '
            'replies = replies + excluded.replies',
            [(t, totals[t], totals_listed[t], totals_replies[t]) for t in set(totals) | set(totals_replies)])
        contacted.save()
        db.executemany(
            'INSERT INTO sources (ip, country, first, last) VALUES (?, NULL, ?, ?) '
            'ON CONFLICT (ip) DO UPDATE SET first = min(first, excluded.first), last = max(last, excluded.last)',
            [(src, first, last) for src, (first, last) in seen.items()])
        db.executemany('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)',
                       [('file', path), ('offset', str(pos))])
    return sum(hits.values())


def read_states(db):
    """ the addresses your network has connections to right now: a state's destination, when it's on the
        internet (one going out; one coming in to a forwarded port has the router or a local address there) """
    try:
        out = subprocess.run(['/sbin/pfctl', '-ss'], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return
    now = int(time.time())
    seen = set()
    for line in out.splitlines():
        words = line.split()
        if '->' in words:
            at = words.index('->') + 1
        elif '<-' in words:
            at = 2
        else:
            continue
        if at >= len(words):
            continue
        addr = words[at]
        addr = addr.split('[')[0] if '[' in addr else addr.rsplit(':', 1)[0]
        try:
            if ipaddress.ip_address(addr).is_global:
                seen.add(addr)
        except ValueError:
            continue
    with db:
        db.executemany('INSERT INTO contacts (ip, last) VALUES (?, ?) '
                       'ON CONFLICT (ip) DO UPDATE SET last = max(last, excluded.last)', [(ip, now) for ip in seen])


def load_geo(db):
    """ copy OPNsense's GeoIP country lists into the database when they change
        :return: True when (re)loaded, False when unchanged, None when there are none """
    try:
        with open(GEO_STATS) as f:
            stamp = json.load(f).get('timestamp') or ''
    except (OSError, ValueError):
        stamp = ''
    current = (db.execute("SELECT value FROM meta WHERE key = 'geo'").fetchone() or [''])[0]
    if stamp == current:
        return False if stamp else None

    rows4, rows6 = [], []
    for path in glob.glob(os.path.join(GEO_DIR, '*-IPv[46]')):
        cc, family = os.path.basename(path).rsplit('-', 1)
        with open(path) as f:
            for line in f:
                try:
                    net = ipaddress.ip_network(line.strip(), strict=False)
                except ValueError:
                    continue
                if family == 'IPv4':
                    rows4.append((int(net.network_address), int(net.broadcast_address), cc))
                else:
                    rows6.append((net.network_address.packed, net.broadcast_address.packed, cc))
    with db:
        db.execute('DELETE FROM geo4')
        db.execute('DELETE FROM geo6')
        db.executemany('INSERT OR REPLACE INTO geo4 VALUES (?, ?, ?)', rows4)
        db.executemany('INSERT OR REPLACE INTO geo6 VALUES (?, ?, ?)', rows6)
        db.execute('UPDATE sources SET country = NULL')     # look everyone up again
        db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('geo', ?)", (stamp,))
    return True if stamp else None


def fill_countries(db):
    todo = [ip for (ip,) in db.execute('SELECT ip FROM sources WHERE country IS NULL')]
    with db:
        db.executemany('UPDATE sources SET country = ? WHERE ip = ?', [(country(db, ip), ip) for ip in todo])


def rollup(db, force=False):
    """ the page's totals for each period, from the hourly (or 5-minute) rows: per source, port and country """
    now = int(time.time())
    built = dict(db.execute('SELECT period, built FROM agg_meta'))
    for hours in PERIODS:
        # the short periods every minute, the long ones every 5 minutes
        if not force and now - built.get(hours, 0) < (50 if hours <= RECENT else 290):
            continue
        start = period_start(hours, now)
        table = hits_table(hours)
        with db:
            for agg in ('agg_meta', 'agg_sources', 'agg_ports', 'agg_countries'):
                db.execute('DELETE FROM %s WHERE period = ?' % agg, (hours,))
            db.execute(
                'INSERT INTO agg_ports SELECT ?, proto, port, sum(packets), count(DISTINCT ip) FROM %s '
                'WHERE hour >= ? GROUP BY proto, port' % table, (hours, start))
            # each source with the port it tried most
            db.execute(
                'INSERT INTO agg_sources SELECT ?, b.ip, coalesce(s.country, \'\'), b.packets, b.ports, b.listed, s.first, '
                's.last, b.top_proto, b.top_port FROM ('
                '  SELECT ip, sum(n) packets, count(*) ports, sum(l) listed, '
                '    max(CASE WHEN rk = 1 THEN proto END) top_proto, max(CASE WHEN rk = 1 THEN port END) top_port FROM ('
                '      SELECT ip, proto, port, sum(packets) n, sum(listed) l, '
                '        row_number() OVER (PARTITION BY ip ORDER BY sum(packets) DESC, proto, port) rk '
                '      FROM %s WHERE hour >= ? GROUP BY ip, proto, port) '
                '  GROUP BY ip) b LEFT JOIN sources s ON s.ip = b.ip' % table, (hours, start))
            db.execute(
                'INSERT INTO agg_countries SELECT ?, country, sum(packets), count(*) FROM agg_sources '
                'WHERE period = ? GROUP BY country', (hours, hours))
            db.execute(
                'INSERT INTO agg_meta SELECT ?, ?, ?, coalesce(sum(packets), 0), coalesce(sum(listed), 0), count(*) '
                'FROM agg_sources WHERE period = ?', (hours, now, start, hours))


def prune(db, cutoff):
    with db:
        db.execute('DELETE FROM hits WHERE hour < ?', (cutoff - cutoff % 3600,))
        db.execute('DELETE FROM totals WHERE t < ?', (cutoff - cutoff % 3600,))
        db.execute('DELETE FROM replies WHERE hour < ?', (cutoff - cutoff % 3600,))
        db.execute('DELETE FROM contacts WHERE last < ?', (int(time.time()) - 86400,))
        db.execute('DELETE FROM sources WHERE last < ?', (cutoff,))


def main():
    lock = open(LOCK, 'w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return                                  # the previous run (a first, long one) is still going
    cutoff = int(time.time()) - DAYS * 86400
    db = connect()
    devices, blocklist_rules = read_config()
    read_logs(db, devices, blocklist_rules, cutoff)
    read_states(db)       # after the log: a packet counts as a reply to a connection seen before it, not after
    geo_changed = load_geo(db)
    if geo_changed is not None:
        fill_countries(db)
    rollup(db, force=geo_changed is True)
    if time.localtime().tm_min == 0:
        prune(db, cutoff)


if __name__ == '__main__':
    main()
