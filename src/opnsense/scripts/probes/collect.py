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
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import connect, read_config, period_start, DAYS, PERIODS  # noqa: E402

LOGS = '/var/log/filter/filter_*.log'
LOCK = '/var/run/probes.lock'
GEO_DIR = '/usr/local/share/GeoIP/alias'
GEO_STATS = '/usr/local/share/GeoIP/alias.stats'

# filterlog's CSV layout (core's scripts/filter/read_log.py): where protocol, source and port are
FIELDS = {'4': (16, 18, 21), '6': (12, 15, 18)}


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

    hits = collections.Counter()
    listed = collections.Counter()
    totals = collections.Counter()
    totals_listed = collections.Counter()
    seen = {}
    for path in files:
        start = offset if path == last_file else 0
        try:
            log = open(path, 'rb')
        except OSError:
            continue
        with log:
            if start > os.fstat(log.fileno()).st_size:
                start = 0                       # the file was replaced
            log.seek(start)
            pos = start
            for raw in log:
                if not raw.endswith(b'\n'):
                    break                       # still being written: next run
                pos += len(raw)
                # most of the log is usually passes: skip them before decoding or parsing anything
                if b',block,in,' not in raw or b'filterlog' not in raw:
                    continue
                parts = raw.decode('utf-8', 'replace').split()
                if len(parts) < 3:
                    continue
                f = parts[-1].split(',')
                if len(f) < 9 or f[6] != 'block' or f[7] != 'in' or f[4] not in devices or f[8] not in FIELDS:
                    continue
                try:
                    when = int(datetime.datetime.fromisoformat(parts[1]).timestamp())
                except ValueError:
                    continue
                if when < cutoff:
                    continue
                p_proto, p_src, p_dport = FIELDS[f[8]]
                if len(f) <= p_src:
                    continue
                proto, src = f[p_proto], f[p_src]
                port = int(f[p_dport]) if proto in ('tcp', 'udp') and len(f) > p_dport and f[p_dport].isdigit() else -1
                key = (when - when % 3600, src, proto, port)
                hits[key] += 1
                totals[when - when % 300] += 1
                if f[3].lower() in blocklist_rules:
                    listed[key] += 1
                    totals_listed[when - when % 300] += 1
                first, last = seen.get(src, (when, when))
                seen[src] = (min(first, when), max(last, when))
        last_file, offset = path, pos

    with db:
        db.executemany(
            'INSERT INTO hits (hour, ip, proto, port, packets, listed) VALUES (?, ?, ?, ?, ?, ?) '
            'ON CONFLICT (hour, ip, proto, port) DO UPDATE SET '
            'packets = packets + excluded.packets, listed = listed + excluded.listed',
            [(*key, n, listed[key]) for key, n in hits.items()])
        db.executemany(
            'INSERT INTO totals (t, packets, listed) VALUES (?, ?, ?) '
            'ON CONFLICT (t) DO UPDATE SET packets = packets + excluded.packets, listed = listed + excluded.listed',
            [(t, n, totals_listed[t]) for t, n in totals.items()])
        db.executemany(
            'INSERT INTO sources (ip, country, first, last) VALUES (?, NULL, ?, ?) '
            'ON CONFLICT (ip) DO UPDATE SET first = min(first, excluded.first), last = max(last, excluded.last)',
            [(src, first, last) for src, (first, last) in seen.items()])
        if last_file:
            db.executemany('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)',
                           [('file', last_file), ('offset', str(offset))])
    return sum(hits.values())


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


def country(db, ip):
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


def fill_countries(db):
    todo = [ip for (ip,) in db.execute('SELECT ip FROM sources WHERE country IS NULL')]
    with db:
        db.executemany('UPDATE sources SET country = ? WHERE ip = ?', [(country(db, ip), ip) for ip in todo])


def rollup(db, force=False):
    """ the page's totals for each period, from the hourly rows: per source, port and country """
    now = int(time.time())
    built = dict(db.execute('SELECT period, built FROM agg_meta'))
    for hours in PERIODS:
        if not force and now - built.get(hours, 0) < 300:
            continue
        start = period_start(hours, now)
        with db:
            for table in ('agg_meta', 'agg_sources', 'agg_ports', 'agg_countries'):
                db.execute('DELETE FROM %s WHERE period = ?' % table, (hours,))
            db.execute(
                'INSERT INTO agg_ports SELECT ?, proto, port, sum(packets), count(DISTINCT ip) FROM hits '
                'WHERE hour >= ? GROUP BY proto, port', (hours, start))
            # each source with the port it tried most
            db.execute(
                'INSERT INTO agg_sources SELECT ?, b.ip, coalesce(s.country, \'\'), b.packets, b.ports, b.listed, s.first, '
                's.last, b.top_proto, b.top_port FROM ('
                '  SELECT ip, sum(n) packets, count(*) ports, sum(l) listed, '
                '    max(CASE WHEN rk = 1 THEN proto END) top_proto, max(CASE WHEN rk = 1 THEN port END) top_port FROM ('
                '      SELECT ip, proto, port, sum(packets) n, sum(listed) l, '
                '        row_number() OVER (PARTITION BY ip ORDER BY sum(packets) DESC, proto, port) rk '
                '      FROM hits WHERE hour >= ? GROUP BY ip, proto, port) '
                '  GROUP BY ip) b LEFT JOIN sources s ON s.ip = b.ip', (hours, start))
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
    geo_changed = load_geo(db)
    if geo_changed is not None:
        fill_countries(db)
    rollup(db, force=geo_changed is True)
    if time.localtime().tm_min == 0:
        prune(db, cutoff)


if __name__ == '__main__':
    main()
