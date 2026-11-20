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
    Answers the page and the widget from the collector's database. JSON on stdout.

      query.py summary <hours>                      totals, countries, top 5 ports and sources
      query.py ports <hours> <sort> <dir> <offset> <limit> [search]
      query.py sources <hours> <sort> <dir> <offset> <limit> [search]
      query.py source <ip> <hours>                  one source: country, first/last seen, ports, hours
"""

import ipaddress
import json
import os
import socket
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import connect, period_start, DAYS, PERIODS  # noqa: E402

PORT_SORT = {'port': 'port', 'service': 'port', 'packets': 'packets', 'sources': 'sources'}
SOURCE_SORT = {'ip': 'ip', 'country': 'country', 'packets': 'packets', 'ports': 'ports',
               'listed': 'listed', 'last': 'last', 'first': 'first'}


def service(proto, port):
    if port < 0:
        return ''
    try:
        return socket.getservbyport(port, proto)
    except (OSError, OverflowError):
        return ''


def since(hours):
    try:
        hours = float(hours)
    except ValueError:
        hours = 24
    hours = min(max(hours, 1), DAYS * 24)
    return period_start(hours, int(time.time()))


def ready(db, hours):
    """ the collector's totals for this period, when it keeps them: (built, since, packets, listed, sources) """
    try:
        hours = int(hours)
    except ValueError:
        return None
    if hours not in PERIODS:
        return None
    return db.execute('SELECT built, since, packets, listed, sources FROM agg_meta WHERE period = ?',
                      (hours,)).fetchone()


def agg_source_row(ip, cc, packets, ports, listed, first, last, top_proto, top_port):
    return {'ip': ip, 'country': cc or '', 'packets': packets, 'ports': ports, 'listed': listed,
            'blocklist': listed > 0, 'first': first, 'last': last,
            'top': {'proto': top_proto, 'port': top_port if top_port >= 0 else None} if top_proto else None}


AGG_SOURCES = 'SELECT ip, country, packets, ports, listed, first, last, top_proto, top_port FROM agg_sources '
AGG_PORTS = 'SELECT proto, port, packets, sources FROM agg_ports '


def port_row(proto, port, packets, sources):
    return {'id': '%s/%d' % (proto, port), 'proto': proto, 'port': port if port >= 0 else None, 'service': service(proto, port),
            'packets': packets, 'sources': sources}


def ports_query(db, start, where='', args=(), order='packets DESC', limit=5, offset=0):
    return [port_row(*r) for r in db.execute(
        'SELECT proto, port, sum(packets) packets, count(DISTINCT ip) sources FROM hits '
        'WHERE hour >= ? %s GROUP BY proto, port ORDER BY %s, proto, port LIMIT ? OFFSET ?' % (where, order),
        (start, *args, limit, offset))]


def sources_query(db, start, where='', args=(), order='packets DESC', limit=5, offset=0):
    rows = db.execute(
        'SELECT h.ip, s.country, sum(h.packets) packets, count(DISTINCT h.proto || h.port) ports, sum(h.listed) listed, '
        's.first, s.last FROM hits h LEFT JOIN sources s ON s.ip = h.ip '
        'WHERE h.hour >= ? %s GROUP BY h.ip ORDER BY %s, h.ip LIMIT ? OFFSET ?' % (where, order),
        (start, *args, limit, offset)).fetchall()
    result = []
    for ip, cc, packets, ports, listed, first, last in rows:
        top = db.execute('SELECT proto, port FROM hits WHERE ip = ? AND hour >= ? GROUP BY proto, port '
                         'ORDER BY sum(packets) DESC LIMIT 1', (ip, start)).fetchone()
        result.append({'ip': ip, 'country': cc or '', 'packets': packets, 'ports': ports, 'listed': listed,
                       'blocklist': listed > 0, 'first': first, 'last': last,
                       'top': {'proto': top[0], 'port': top[1] if top[1] >= 0 else None} if top else None})
    return result


def summary(db, hours):
    agg = ready(db, hours)
    if agg:
        return fast_summary(db, int(hours), agg)
    start = since(hours)
    packets, listed, sources = db.execute(
        'SELECT coalesce(sum(packets), 0), coalesce(sum(listed), 0), count(DISTINCT ip) FROM hits WHERE hour >= ?',
        (start,)).fetchone()
    countries = [{'country': cc, 'packets': n, 'sources': s} for cc, n, s in db.execute(
        "SELECT coalesce(s.country, '') cc, sum(h.packets) n, count(DISTINCT h.ip) FROM hits h "
        'LEFT JOIN sources s ON s.ip = h.ip WHERE h.hour >= ? GROUP BY cc ORDER BY n DESC', (start,))]
    first = db.execute('SELECT min(hour) FROM hits').fetchone()[0]
    step, points = series(db, start)
    geo = db.execute("SELECT value FROM meta WHERE key = 'geo'").fetchone()
    return {'since': start, 'data_since': first, 'packets': packets, 'listed': listed, 'sources': sources,
            'geoip': bool(geo and geo[0]), 'countries': countries, 'step': step, 'series': points,
            'ports': ports_query(db, start), 'top_sources': sources_query(db, start)}


def series(db, start):
    """ the graph: 5-minute steps for a day or two, hourly for up to 10 days, then 4-hourly """
    span = int(time.time()) - start
    step = 300 if span <= 2 * 86400 else 3600 if span <= 10 * 86400 else 4 * 3600
    return step, db.execute('SELECT t - t % ? s, sum(packets), sum(listed) FROM totals WHERE t >= ? GROUP BY s ORDER BY s',
                            (step, start)).fetchall()


def fast_summary(db, hours, agg):
    built, start, packets, listed, sources = agg
    step, points = series(db, start)
    geo = db.execute("SELECT value FROM meta WHERE key = 'geo'").fetchone()
    return {
        'since': start, 'built': built, 'data_since': db.execute('SELECT min(hour) FROM hits').fetchone()[0],
        'packets': packets, 'listed': listed, 'sources': sources, 'geoip': bool(geo and geo[0]),
        'countries': [{'country': cc, 'packets': n, 'sources': s} for cc, n, s in db.execute(
            'SELECT country, packets, sources FROM agg_countries WHERE period = ? ORDER BY packets DESC', (hours,))],
        'step': step, 'series': points,
        'ports': [port_row(*r) for r in db.execute(AGG_PORTS + 'WHERE period = ? ORDER BY packets DESC LIMIT 5', (hours,))],
        'top_sources': [agg_source_row(*r) for r in db.execute(
            AGG_SOURCES + 'WHERE period = ? ORDER BY packets DESC LIMIT 5', (hours,))]
    }


def fast_grid(db, kind, hours, order, text, offset, limit):
    """ a grid page from the collector's totals; None when the search needs the hourly rows """
    text = text.strip()
    where, args = 'WHERE period = ?', [hours]
    if kind == 'ports':
        if text:
            w, a = search_clause('ports', text)
            where += ' ' + w
            args += list(a)
        query, row = AGG_PORTS, port_row
    else:
        codes, text = split_search(text)
        if text.isdigit():
            return None                         # sources that tried this port: only the hourly rows know
        if codes:
            where += ' AND country IN (%s)' % ','.join('?' * len(codes))
            args += codes
        if not text:
            pass
        elif len(text) == 2 and text.isalpha():
            where += ' AND (country = ? OR ip LIKE ?)'
            args += [text.upper(), text + '%']
        elif text:
            where += ' AND ip LIKE ?'
            args.append(text + '%')
        query, row = AGG_SOURCES, agg_source_row
    total = db.execute('SELECT count(*) FROM %s %s' % ('agg_ports' if kind == 'ports' else 'agg_sources', where),
                       args).fetchone()[0]
    tiebreak = 'proto, port' if kind == 'ports' else 'ip'
    rows = db.execute(query + '%s ORDER BY %s, %s LIMIT ? OFFSET ?' % (where, order, tiebreak),
                      (*args, limit, offset)).fetchall()
    return {'rows': [row(*r) for r in rows], 'total': total}


def country_codes(text):
    """ 'cc:US,GB,AE': a country filter (the page's country list, or a country's name typed in the search box) """
    if not text.lower().startswith('cc:'):
        return []
    return [c.upper() for c in text[3:].split(',') if len(c) == 2 and c.isalpha()][:300]


def split_search(text):
    """ :return: (country codes, the rest of the search) """
    codes, rest = [], []
    for word in text.split():
        found = country_codes(word)
        if found:
            codes += found
        else:
            rest.append(word)
    return codes, ' '.join(rest)


def search_clause(kind, text):
    """ a search box: an address prefix, a port, a protocol or service name, or a country code """
    text = text.strip()
    if not text:
        return '', ()
    if kind == 'ports':
        if text.isdigit():
            return 'AND port = ?', (int(text),)
        try:
            ports = {socket.getservbyname(text.lower(), p) for p in ('tcp', 'udp') if _has(text.lower(), p)}
        except OSError:
            ports = set()
        if ports:
            return 'AND port IN (%s)' % ','.join('?' * len(ports)), tuple(ports)
        return 'AND proto = ?', (text.lower(),)
    codes, text = split_search(text)
    where, args = '', ()
    if codes:
        where, args = 'AND s.country IN (%s)' % ','.join('?' * len(codes)), tuple(codes)
    if not text:
        return where, args
    if len(text) == 2 and text.isalpha():
        return where + ' AND (s.country = ? OR h.ip LIKE ?)', args + (text.upper(), text + '%')
    if text.isdigit():
        return where + ' AND (h.port = ? OR h.ip LIKE ?)', args + (int(text), text + '%')
    return where + ' AND h.ip LIKE ?', args + (text + '%',)


def _has(name, proto):
    try:
        socket.getservbyname(name, proto)
        return True
    except OSError:
        return False


def grid(db, kind, hours, sort, direction, offset, limit, text=''):
    start = since(hours)
    order = (PORT_SORT if kind == 'ports' else SOURCE_SORT).get(sort, 'packets')
    order += ' ASC' if direction == 'asc' else ' DESC'
    offset, limit = max(int(offset), 0), min(max(int(limit), 1), 500)
    if ready(db, hours):
        result = fast_grid(db, kind, int(hours), order, text, offset, limit)
        if result is not None:
            return result
    where, args = search_clause(kind, text)
    if kind == 'ports':
        rows = ports_query(db, start, where, args, order, limit, offset)
        total = db.execute('SELECT count(*) FROM (SELECT 1 FROM hits WHERE hour >= ? %s GROUP BY proto, port)'
                           % where, (start, *args)).fetchone()[0]
    else:
        rows = sources_query(db, start, where, args, order, limit, offset)
        total = db.execute('SELECT count(*) FROM (SELECT 1 FROM hits h LEFT JOIN sources s ON s.ip = h.ip '
                           'WHERE h.hour >= ? %s GROUP BY h.ip)' % where, (start, *args)).fetchone()[0]
    return {'rows': rows, 'total': total}


def source(db, ip, hours):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return {'error': 'not an address'}
    start = since(hours)
    info = db.execute('SELECT country, first, last FROM sources WHERE ip = ?', (ip,)).fetchone()
    hourly = db.execute('SELECT hour, sum(packets) FROM hits WHERE ip = ? AND hour >= ? GROUP BY hour ORDER BY hour',
                        (ip, start)).fetchall()
    ports = db.execute('SELECT proto, port, sum(packets) n, sum(listed) FROM hits WHERE ip = ? AND hour >= ? '
                       'GROUP BY proto, port ORDER BY n DESC LIMIT 100', (ip, start)).fetchall()
    nports = db.execute('SELECT count(*) FROM (SELECT 1 FROM hits WHERE ip = ? AND hour >= ? GROUP BY proto, port)',
                        (ip, start)).fetchone()[0]
    return {'ip': ip, 'country': (info[0] if info else '') or '', 'first': info[1] if info else None,
            'last': info[2] if info else None, 'since': start,
            'packets': sum(n for _, n in hourly), 'listed': sum(r[3] for r in ports) > 0, 'nports': nports,
            'hours': hourly,
            'ports': [{'proto': p, 'port': q if q >= 0 else None, 'service': service(p, q), 'packets': n}
                      for p, q, n, _ in ports]}


def main(argv):
    db = connect(readonly=True)
    if db is None:
        return {'error': 'nodata'}
    cmd = argv[0] if argv else ''
    if cmd == 'summary' and len(argv) >= 2:
        return summary(db, argv[1])
    if cmd in ('ports', 'sources') and len(argv) >= 6:
        return grid(db, cmd, *argv[1:6], ' '.join(argv[6:]))
    if cmd == 'source' and len(argv) >= 3:
        return source(db, argv[1], argv[2])
    return {'error': 'usage: summary|ports|sources|source ...'}


if __name__ == '__main__':
    try:
        result = main(sys.argv[1:])
    except sqlite3.OperationalError:
        result = {'error': 'nodata'}        # the collector hasn't made its tables yet
    print(json.dumps(result))
