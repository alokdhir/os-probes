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
    whois.py <ip>: who an address belongs to, from its regional registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
    over RDAP, whois' JSON successor. Only run when someone asks (the Whois button in a source's detail);
    answers are kept a week. IANA's list of which registry holds which addresses is kept a month.
"""

import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import connect, DB  # noqa: E402

BOOTSTRAP = 'https://data.iana.org/rdap/ipv%d.json'
KEEP = 7 * 86400
HEADERS = {'Accept': 'application/rdap+json, application/json', 'User-Agent': 'OPNsense-probes'}


def fetch(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=HEADERS), timeout=15) as response:
        return json.load(response)


def registry(addr):
    """ the RDAP service for an address, from IANA's bootstrap list """
    path = os.path.join(os.path.dirname(DB), 'rdap-ipv%d.json' % addr.version)
    try:
        if time.time() - os.path.getmtime(path) > 30 * 86400:
            raise OSError
        with open(path) as f:
            services = json.load(f)['services']
    except (OSError, ValueError, KeyError):
        data = fetch(BOOTSTRAP % addr.version)
        with open(path + '.tmp', 'w') as f:
            json.dump(data, f)
        os.replace(path + '.tmp', path)
        services = data['services']
    best, url = -1, None
    for prefixes, urls in services:
        for prefix in prefixes:
            try:
                net = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue
            if addr in net and net.prefixlen > best:
                https = [u for u in urls if u.startswith('https://')]
                if https:
                    best, url = net.prefixlen, https[0]
    return url


def vcard(entity):
    """ a contact's name, organisation and e-mail addresses """
    card = {'emails': [], 'kind': ''}
    try:
        fields = entity['vcardArray'][1]
    except (KeyError, IndexError, TypeError):
        return card
    for field in fields:
        if len(field) < 4:
            continue
        name, value = field[0], field[3]
        if name in ('fn', 'org', 'kind') and isinstance(value, str) and value.strip() and not card.get(name):
            card[name] = value.strip()
        elif name == 'email' and isinstance(value, str):
            card['emails'].append(value.strip())
    return card


def entities(node):
    for entity in node.get('entities') or []:
        yield entity
        yield from entities(entity)


def text(remark):
    return ' '.join(line.strip() for line in remark.get('description') or [] if line.strip())


def distill(data, url):
    """ the parts of an RDAP answer worth showing """
    abuse = []
    registrants, others = [], []
    for entity in entities(data):
        roles = set(entity.get('roles') or [])
        card = vcard(entity)
        if 'abuse' in roles:
            abuse += card['emails']
        # RIPE lists the maintainer accounts (mnt-..., ...-MNT) as registrants too: not who owns the network
        if 'registrant' in roles and 'mnt' not in (entity.get('handle') or '').lower():
            registrants.append(card)
        elif roles & {'administrative', 'technical'}:
            others.append(card)
    remarks = [text(r) for r in data.get('remarks') or []]
    names = [c.get('fn') for c in registrants if c['kind'] == 'org'] + [c.get('fn') for c in registrants] + \
        [r for r in remarks if r][:1] + [c.get('fn') for c in others]
    owner = next((n for n in names if n), '')
    cidrs = ['%s/%s' % (c.get('v4prefix') or c.get('v6prefix'), c.get('length'))
             for c in data.get('cidr0_cidrs') or [] if (c.get('v4prefix') or c.get('v6prefix'))]
    events = {e.get('eventAction'): (e.get('eventDate') or '')[:10] for e in data.get('events') or []}
    link = next((l.get('href') for l in data.get('links') or [] if l.get('rel') == 'self'), url)
    if not isinstance(link, str) or not link.startswith('https://'):
        link = url                              # the page links to it: never a javascript: or other scheme
    return {
        'name': data.get('name') or '', 'owner': owner,
        'handle': '' if ' ' in (data.get('handle') or ' ') else data['handle'],     # RIPE's is the range again
        'description': ' · '.join(r for r in remarks if r)[:400],
        'range': '%s – %s' % (data.get('startAddress'), data.get('endAddress')) if data.get('startAddress') else '',
        'cidr': ', '.join(cidrs), 'country': data.get('country') or '', 'type': data.get('type') or '',
        'abuse': sorted(set(abuse)), 'registered': events.get('registration', ''),
        'changed': events.get('last changed', ''), 'registry': urllib.parse.urlparse(link).hostname or '',
        'url': link,
    }


def lookup(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {'error': 'not an address'}
    if not addr.is_global:
        return {'error': 'not a public address'}
    db = connect()
    db.execute('CREATE TABLE IF NOT EXISTS whois (ip TEXT PRIMARY KEY, fetched INTEGER, data TEXT) WITHOUT ROWID')
    row = db.execute('SELECT fetched, data FROM whois WHERE ip = ?', (str(addr),)).fetchone()
    if row and time.time() - row[0] < KEEP:
        cached = json.loads(row[1])
        if not str(cached.get('url', '')).startswith('https://'):
            cached['url'] = ''
        return dict(cached, fetched=row[0])
    try:
        base = registry(addr)
        if not base:
            return {'error': 'no registry for this address'}
        url = base.rstrip('/') + '/ip/' + str(addr)
        result = distill(fetch(url), url)
    except urllib.error.HTTPError as e:
        return {'error': 'the registry answered %d' % e.code}
    except (OSError, ValueError) as e:
        return {'error': 'no answer from the registry (%s)' % getattr(e, 'reason', e)}
    now = int(time.time())
    with db:
        db.execute('INSERT OR REPLACE INTO whois VALUES (?, ?, ?)', (str(addr), now, json.dumps(result)))
        db.execute('DELETE FROM whois WHERE fetched < ?', (now - KEEP,))
    return dict(result, fetched=now)


if __name__ == '__main__':
    print(json.dumps(lookup(sys.argv[1] if len(sys.argv) > 1 else '')))
