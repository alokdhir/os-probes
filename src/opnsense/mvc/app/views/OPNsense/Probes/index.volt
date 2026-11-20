{#
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
#}

<script src="{{ cache_safe('/ui/js/chart.umd.min.js') }}"></script>
<script src="{{ cache_safe('/ui/js/d3.min.js') }}"></script>
<style>
    .probes-bar { padding: 10px 15px; display: flex; flex-wrap: wrap; gap: 6px 16px; align-items: center; }
    .probes-totals { font-size: 13px; }
    .probes-key { display: inline-block; width: 9px; height: 9px; border-radius: 2px; margin: 0 4px 0 2px; }
    .probes-note { color: #888; font-size: 12px; }
    .probes-whois-btn { float: right; margin-left: 12px; }
    .probes-whois-table { width: auto; margin-bottom: 2px; }
    .probes-whois-table th { color: #888; font-weight: normal; padding-right: 16px !important; white-space: nowrap; }
    .probes-replies { color: #888; border-bottom: 1px dotted #888; cursor: help; }
    .probes-section { padding: 0 15px 10px; }
    .probes-section h3 { font-size: 14px; font-weight: bold; margin: 12px 0 6px; }
    #probes-tab-map h3 { margin-top: 6px; }
    .probes-map { width: 100%; }
    .probes-map svg { width: 100%; height: auto; display: block; }
    .probes-map path { stroke: rgba(128,128,128,0.6); stroke-width: 0.4; cursor: default; }
    .probes-map path.probes-has { cursor: pointer; }
    .probes-map path:hover { stroke: #333; stroke-width: 1; }
    .probes-legend { display: flex; align-items: center; gap: 6px; color: #888; font-size: 11px; margin-top: 4px; }
    .probes-legend .probes-ramp { width: 120px; height: 8px; border-radius: 2px; }
    .probes-tip { position: fixed; pointer-events: none; z-index: 2000; background: rgba(30,30,30,0.92); color: #fff;
                  padding: 5px 8px; border-radius: 4px; font-size: 12px; display: none; white-space: nowrap; }
    .probes-countries td, .probes-countries th { padding: 3px 6px !important; font-size: 12px; }
    .probes-countries tr { cursor: pointer; }
    .probes-bar-cell { position: relative; }
    .probes-bar-cell span { position: absolute; left: 0; top: 3px; bottom: 3px; background: rgba(54,162,235,0.2); border-radius: 2px; }
    .probes-bar-cell em { position: relative; font-style: normal; }
    .probes-tag { font-size: 10px; padding: 1px 5px; border-radius: 3px; color: #fff; background: rgb(255,99,71); margin-left: 4px; }
    .probes-detail-ports td, .probes-detail-ports th { padding: 2px 6px !important; font-size: 12px; }
</style>

<script>
    $(document).ready(function () {
        const BLUE = 'rgba(54,162,235,1)', BLUE_FILL = 'rgba(54,162,235,0.25)';
        const RED = 'rgba(255,99,71,1)', RED_FILL = 'rgba(255,99,71,0.45)';
        const regions = (typeof Intl !== 'undefined' && Intl.DisplayNames)
            ? new Intl.DisplayNames(undefined, {type: 'region'}) : null;
        let hours = 24;
        let summary = null;
        let chart = null;
        let world = null;
        const grids = {};

        function esc(s) {
            const plain = s == null ? '' : String(s).includes('&') ? $('<textarea/>').html(String(s)).text() : String(s);
            return plain.replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'})[c]);
        }
        const num = n => Math.round(n || 0).toLocaleString();
        /* a pill per blocklist that blocked the source (just "blocklist" when the name isn't known) */
        const listTags = names => (names && names.length ? names : ['{{ lang._('blocklist') }}'])
            .map(n => `<span class="probes-tag">${esc(n)}</span>`).join('');
        const countryName = cc => !cc ? '{{ lang._('Unknown') }}' : (regions ? (regions.of(cc) || cc) : cc);
        const portText = r => r && (r.port !== null && r.port !== undefined ? `${r.proto}/${r.port}` : r ? r.proto : '');
        function ago(t) {
            if (!t) return '';
            const s = Date.now() / 1000 - t;
            if (s < 120) return '{{ lang._('just now') }}';
            if (s < 7200) return Math.round(s / 60) + ' {{ lang._('min ago') }}';
            if (s < 172800) return Math.round(s / 3600) + ' {{ lang._('h ago') }}';
            return Math.round(s / 86400) + ' {{ lang._('days ago') }}';
        }
        function when(t) {
            return t ? new Date(t * 1000).toLocaleString([], {month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'}) : '';
        }

        /* ---- the graph ---- */
        function drawChart() {
            const s = summary;
            const labels = s.series.map(r => r[0] * 1000);
            const perMin = s.step / 60;
            const data = [s.series.map(r => (r[2] || 0) / perMin), s.series.map(r => (r[1] || 0) / perMin)];
            if (!chart) {
                chart = new Chart($('#probes-chart')[0].getContext('2d'), {
                    type: 'line',
                    data: {labels: labels, datasets: [
                        {label: '{{ lang._('by blocklists') }}', data: data[0], borderColor: RED, backgroundColor: RED_FILL, fill: 'origin'},
                        {label: '{{ lang._('blocked') }}', data: data[1], borderColor: BLUE, backgroundColor: BLUE_FILL, fill: 'origin'}
                    ]},
                    options: {
                        maintainAspectRatio: false, animation: false,
                        interaction: {mode: 'index', intersect: false},
                        elements: {line: {borderWidth: 1.5, cubicInterpolationMode: 'monotone'}, point: {radius: 0, hoverRadius: 3}},
                        plugins: {legend: {display: false}, tooltip: {itemSort: (a, b) => b.datasetIndex - a.datasetIndex, callbacks: {
                            title: items => new Date(chart.data.labels[items[0].dataIndex]).toLocaleString([], {weekday: 'short', hour: 'numeric', minute: '2-digit'}),
                            label: c => `${c.dataset.label}: ${c.raw.toFixed(c.raw < 10 ? 1 : 0)} {{ lang._('packets/min') }}`
                        }}},
                        scales: {
                            x: {ticks: {maxTicksLimit: 8, maxRotation: 0, color: '#888', callback: function (v) {
                                const d = new Date(this.getLabelForValue(v));
                                return hours <= 3 ? d.toLocaleTimeString([], {hour: 'numeric', minute: '2-digit'})
                                    : hours <= 48 ? d.toLocaleTimeString([], {hour: 'numeric'})
                                    : d.toLocaleDateString([], {month: 'short', day: 'numeric'});
                            }}, grid: {display: false}},
                            y: {beginAtZero: true, ticks: {color: '#888', maxTicksLimit: 5}, grid: {color: 'rgba(128,128,128,0.15)'},
                                title: {display: true, text: '{{ lang._('packets/min') }}', color: '#888'}}
                        }
                    }
                });
            } else {
                chart.data.labels = labels;
                chart.data.datasets[0].data = data[0];
                chart.data.datasets[1].data = data[1];
                chart.update();
            }
        }

        /* ---- the map and the country list ---- */
        function color(t) {
            /* 0..1 -> light to the graph's blue */
            const a = 0.12 + 0.88 * t;
            return `rgba(54,162,235,${a.toFixed(2)})`;
        }
        function drawMap() {
            const box = $('#probes-map');
            if (!summary.geoip) {
                box.html(`<p class="probes-note">{{ lang._('Countries need the GeoIP database that OPNsense downloads for GeoIP aliases.') }}
                    <a href="/ui/firewall/alias#geoip">{{ lang._('Set it up in Firewall: Aliases, GeoIP settings') }}</a>.</p>`);
                return;
            }
            if (!world) return;
            const byCc = {};
            summary.countries.forEach(c => { if (c.country) byCc[c.country] = c; });
            const max = Math.max(1, ...summary.countries.filter(c => c.country).map(c => c.packets));
            const scale = n => Math.log(1 + n) / Math.log(1 + max);
            const width = 960, height = 470;
            box.empty();
            const svg = d3.select(box[0]).append('svg').attr('viewBox', `0 0 ${width} ${height}`);
            const projection = d3.geo.equirectangular().scale(153).translate([width / 2, height / 2 + 40]);
            const path = d3.geo.path().projection(projection);
            const tip = $('#probes-tip');
            svg.selectAll('path').data(world.features).enter().append('path')
                .attr('d', path)
                .attr('class', f => byCc[f.id] ? 'probes-has' : '')
                .attr('fill', f => byCc[f.id] ? color(scale(byCc[f.id].packets)) : 'rgba(128,128,128,0.12)')
                .on('mousemove', function (f) {
                    const c = byCc[f.id];
                    tip.html(`<strong>${esc(countryName(f.id) || f.properties.name)}</strong><br>`
                        + (c ? `${num(c.packets)} {{ lang._('packets') }} · ${num(c.sources)} ${c.sources === 1 ? '{{ lang._('source') }}' : '{{ lang._('sources') }}'}`
                             : '{{ lang._('nothing blocked') }}'))
                        .css({left: d3.event.clientX + 12, top: d3.event.clientY + 12}).show();
                })
                .on('mouseout', () => tip.hide())
                .on('click', f => { if (byCc[f.id]) showCountry(f.id); });
            $('#probes-legend').html(`<span>1</span><span class="probes-ramp"
                style="background: linear-gradient(to right, ${color(0)}, ${color(1)})"></span>
                <span>${num(max)} {{ lang._('packets (log scale)') }}</span>`);
        }
        function drawCountries() {
            const rows = summary.countries.slice(0, 12);
            const max = Math.max(1, ...rows.map(c => c.packets));
            $('#probes-countries tbody').html(rows.map(c => `<tr data-cc="${esc(c.country)}">
                <td class="probes-bar-cell"><span style="width:${(100 * c.packets / max).toFixed(1)}%"></span><em>${esc(countryName(c.country))}</em></td>
                <td class="text-right">${num(c.packets)}</td><td class="text-right">${num(c.sources)}</td></tr>`).join(''));
        }
        function showCountry(cc) {
            if (!cc) return;
            $('a[href="#probes-tab-sources"]').tab('show');
            setCountry(cc);
            $('html, body').animate({scrollTop: $('#grid-sources').closest('.tab-content').offset().top - 80}, 200);
        }
        $('#probes-countries').on('click', 'tr[data-cc]', function () { showCountry($(this).data('cc')); });

        /* ---- totals ---- */
        function drawTotals() {
            const s = summary;
            $('#probes-totals').html(
                `<span class="probes-key" style="background:${BLUE}"></span><strong>${num(s.packets)}</strong> {{ lang._('packets blocked') }}`
                + ` &nbsp;<span class="probes-key" style="background:${RED}"></span><strong>${num(s.listed)}</strong> {{ lang._('by blocklists') }}`
                + ` &nbsp;· <strong>${num(s.sources)}</strong> {{ lang._('sources') }}`);
            if (s.replies) {
                const who = (s.reply_sources || []).map(r => `${r.ip}${r.country ? ' (' + countryName(r.country) + ')' : ''}: ${num(r.packets)}`);
                $('#probes-totals').append(` &nbsp;· <span class="probes-replies" title="${esc('{{ lang._('Blocked packets from addresses your network had just connected to: late replies to connections that already closed, or a peer-to-peer VPN trying ports. Most:') }}\n' + who.join('\n'))}">`
                    + `${num(s.replies)} {{ lang._('late replies not counted') }}</span>`);
            }
            const note = [];
            if (s.data_since && s.data_since > s.since + 3600) note.push('{{ lang._('Data since') }} ' + when(s.data_since));
            $('#probes-note').text(note.join(' · '));
        }

        function load() {
            ajaxGet('/api/probes/report/summary/' + hours, {}, function (data) {
                if (!data || data.error) {
                    $('#probes-totals').text(data && data.error === 'nodata'
                        ? '{{ lang._('No data yet: the first summary appears within a minute or two.') }}' : '{{ lang._('No answer from the collector.') }}');
                    return;
                }
                summary = data;
                drawTotals();
                drawChart();
                drawCountries();
                fillCountries();
                drawMap();
            });
            Object.keys(grids).forEach(id => $('#' + id).bootgrid('reload'));
        }

        /* ---- the grids ---- */
        const formatters = {
            port: (column, row) => `<a href="#" class="probes-port" data-q="${esc(portText(row))}"
                title="{{ lang._('Sources that tried it') }}">${esc(portText(row))}</a>`,
            service: (column, row) => esc(row.service || ''),
            num: (column, row) => num(row[column.id]),
            ip: (column, row) => `<a href="#" class="probes-source" data-ip="${esc(row.ip)}">${esc(row.ip)}</a>`
                + (row.blocklist ? listTags(row.lists) : ''),
            country: (column, row) => esc(row.country ? countryName(row.country) : ''),
            top: (column, row) => esc(portText(row.top)),
            ago: (column, row) => `<span title="${esc(when(row[column.id]))}">${esc(ago(row[column.id]))}</span>`
        };
        /* a country's name in the search box: the codes of the countries whose name contains it ("united": US, GB, AE) */
        function countrySearch(text) {
            const q = (text || '').trim().toLowerCase();
            if (q.length < 3 || !/^[a-z .'()-]+$/.test(q)) return null;
            const codes = new Set((summary ? summary.countries.map(c => c.country) : [])
                .concat(world ? world.features.map(f => f.id) : []).filter(Boolean));
            const found = [...codes].filter(cc => countryName(cc).toLowerCase().includes(q));
            return found.length ? 'cc:' + found.join(',') : null;
        }
        function grid(id, endpoint) {
            grids[id] = $('#' + id).UIBootgrid({
                search: endpoint,
                options: {
                    selection: false, multiSelect: false,
                    requestHandler: request => {
                        request.hours = hours;
                        if (id === 'grid-sources') request.country = $('#probes-country').val() || '';
                        if (id === 'grid-sources' && request.searchPhrase) {
                            request.searchPhrase = countrySearch(request.searchPhrase) || request.searchPhrase;
                        }
                        return request;
                    },
                    formatters: formatters
                }
            });
        }
        /* the Sources tab's country filter: the countries in the period, most packets first */
        function fillCountries() {
            const pick = $('#probes-country');
            const current = pick.val() || '';
            const known = summary.countries.filter(c => c.country);
            pick.html(`<option value="">{{ lang._('All countries') }}</option>` + known
                .map(c => `<option value="${esc(c.country)}" data-subtext="${num(c.packets)}">${esc(countryName(c.country))}</option>`).join(''));
            pick.val(known.some(c => c.country === current) ? current : '');
            $('#probes-countrypick').toggle(!!summary.geoip);
            pick.selectpicker('refresh');
        }
        function setCountry(cc) {
            $('#probes-country').val(cc).selectpicker('refresh');
            $('#grid-sources').bootgrid('reload');
        }


        /* a port: the sources that tried it (all countries) */
        $(document).on('click', '.probes-port', function (e) {
            e.preventDefault();
            $('#probes-country').val('').selectpicker('refresh');
            $('a[href="#probes-tab-sources"]').tab('show');
            /* core's grid (opnsense_bootgrid.js) searches on keyup of its search box, and shows its clear button on input */
            $('#grid-sources-search-field').val($(this).data('q')).trigger('input').trigger($.Event('keyup', {which: 13}));
        });

        /* who an address belongs to: asks its regional registry (RDAP), only when the Whois button is pressed */
        function whois(ip, target, done) {
            ajaxGet('/api/probes/report/whois/' + encodeURIComponent(ip), {}, function (w) {
                done();
                if (!w || w.error) {
                    target.hide().html(`<p class="probes-note">{{ lang._('Whois') }}: ${esc(w && w.error ? w.error : '{{ lang._('no answer') }}')}</p>`).slideDown(200);
                    return;
                }
                const rows = [
                    ['{{ lang._('Owner') }}', w.owner],
                    ['{{ lang._('Network') }}', [w.name, w.handle && w.handle !== w.name ? `(${w.handle})` : ''].join(' ')],
                    ['{{ lang._('Range') }}', w.cidr && !w.cidr.includes(',') ? w.cidr : w.range],
                    /* where the holder is registered, which often isn't where the address is used (the GeoIP country above) */
                    ['{{ lang._('Registered in') }}', w.country ? countryName(w.country) : ''],
                    ['{{ lang._('Abuse contact') }}', (w.abuse || []).join(', ')],
                    ['{{ lang._('Registered on') }}', [w.registered, w.changed ? `{{ lang._('changed') }} ${w.changed}` : ''].filter(Boolean).join(' · ')],
                    ['{{ lang._('Remarks') }}', w.description !== w.owner ? w.description : ''],
                ].filter(r => r[1] && String(r[1]).trim());
                target.hide().html(`<table class="table table-condensed probes-whois-table"><tbody>`
                    + rows.map(r => `<tr><th>${r[0]}</th><td>${esc(r[1])}</td></tr>`).join('')
                    + `</tbody></table><p class="probes-note">{{ lang._('From') }} <a href="${esc(w.url)}" target="_blank" rel="noopener">${esc(w.registry)}</a>`
                    + ` · ${esc(when(w.fetched))}</p>`).slideDown(250);
            });
        }

        /* ---- one source ---- */
        $(document).on('click', '.probes-source', function (e) {
            e.preventDefault();
            const ip = $(this).data('ip');
            ajaxGet('/api/probes/report/source/' + encodeURIComponent(ip) + '/' + hours, {}, function (d) {
                if (!d || d.error) return;
                const body = $('<div/>');
                body.append(`<button type="button" class="btn btn-default btn-xs probes-whois-btn" title="{{ lang._('Ask the registry who this address belongs to') }}">`
                    + `<i class="fa fa-fw fa-id-card-o"></i> {{ lang._('Whois') }}</button>`);
                body.append(`<p>${esc(countryName(d.country))}${d.listed ? ' ' + listTags(d.lists) : ''}<br>
                    <span class="probes-note">{{ lang._('First seen') }} ${esc(when(d.first))} · {{ lang._('last seen') }} ${esc(when(d.last))}</span><br>
                    <strong>${num(d.packets)}</strong> {{ lang._('packets') }} · <strong>${num(d.nports)}</strong> ${d.nports === 1 ? '{{ lang._('port') }}' : '{{ lang._('ports') }}'}</p>`);
                body.append('<div class="probes-whois"></div>');
                body.append('<div style="height: 140px"><canvas></canvas></div>');
                body.append(`<table class="table table-condensed table-striped probes-detail-ports"><thead><tr>
                    <th>{{ lang._('Port') }}</th><th>{{ lang._('Service') }}</th><th class="text-right">{{ lang._('Packets') }}</th></tr></thead><tbody>`
                    + d.ports.map(p => `<tr><td>${esc(portText(p))}</td><td>${esc(p.service)}</td><td class="text-right">${num(p.packets)}</td></tr>`).join('')
                    + '</tbody></table>' + (d.nports > d.ports.length ? `<p class="probes-note">{{ lang._('The 100 ports with the most packets.') }}</p>` : ''));
                BootstrapDialog.show({
                    title: esc(d.ip), message: body, size: BootstrapDialog.SIZE_WIDE,
                    buttons: [{label: '{{ lang._('Close') }}', action: dlg => dlg.close()}],
                    onshown: function (dlg) {
                        body.find('.probes-whois-btn').on('click', function () {
                            const btn = $(this).prop('disabled', true);
                            btn.find('i').attr('class', 'fa fa-fw fa-spinner fa-pulse');
                            whois(d.ip, body.find('.probes-whois'), () => btn.find('i').attr('class', 'fa fa-fw fa-id-card-o'));
                        });
                        /* every hour of the period, empty ones too */
                        const filled = new Map(d.hours.map(h => [h[0], h[1]]));
                        const labels = [], values = [];
                        const now = Math.floor(Date.now() / 1000);
                        for (let t = d.since; t <= now; t += d.step) { labels.push(t * 1000); values.push(filled.get(t) || 0); }
                        new Chart(body.find('canvas')[0].getContext('2d'), {
                            type: 'bar',
                            data: {labels: labels, datasets: [{data: values, backgroundColor: d.listed ? RED : BLUE}]},
                            options: {maintainAspectRatio: false, animation: false, plugins: {legend: {display: false}, tooltip: {callbacks: {
                                title: items => new Date(labels[items[0].dataIndex]).toLocaleString([], {weekday: 'short', hour: 'numeric', minute: '2-digit'}),
                                label: c => `${num(c.raw)} {{ lang._('packets') }}`}}},
                                scales: {x: {ticks: {maxTicksLimit: 6, maxRotation: 0, color: '#888', callback: function (v) {
                                    const t = new Date(this.getLabelForValue(v));
                                    return hours <= 3 ? t.toLocaleTimeString([], {hour: 'numeric', minute: '2-digit'})
                                        : hours <= 48 ? t.toLocaleTimeString([], {hour: 'numeric'}) : t.toLocaleDateString([], {month: 'short', day: 'numeric'});
                                }}, grid: {display: false}}, y: {beginAtZero: true, ticks: {color: '#888', maxTicksLimit: 4}}}}
                        });
                    }
                });
            });
        });

        /* ---- period ---- */
        $('.probes-period .btn').click(function () {
            hours = parseInt($(this).data('hours'));
            $('.probes-period .btn').removeClass('active').filter(`[data-hours="${hours}"]`).addClass('active');
            load();
        });
        $('.probes-period .btn').filter(`[data-hours="${hours}"]`).addClass('active');

        $.getJSON('/ui/js/probes/world.json').done(data => { world = data; if (summary) drawMap(); });
        grid('grid-sources', '/api/probes/report/search_sources');
        /* the country filter sits after the grid's search box, as core's dnsmasq page places its tag filter */
        $('#probes-countrypick').detach().insertAfter($('#grid-sources-header .actionBar .search'));
        $('#probes-country').selectpicker().on('changed.bs.select', () => $('#grid-sources').bootgrid('reload'));
        grid('grid-ports', '/api/probes/report/search_ports');
        load();
        setInterval(() => { if (!document.hidden) load(); }, 60000);
    });
</script>

<div id="probes-tip" class="probes-tip"></div>
<div class="content-box">
    <div class="probes-bar">
        <div class="btn-group probes-period">
            <button type="button" class="btn btn-default btn-sm" data-hours="1">{{ lang._('1 hour') }}</button>
            <button type="button" class="btn btn-default btn-sm" data-hours="3">{{ lang._('3 hours') }}</button>
            <button type="button" class="btn btn-default btn-sm" data-hours="24">{{ lang._('24 hours') }}</button>
            <button type="button" class="btn btn-default btn-sm" data-hours="168">{{ lang._('7 days') }}</button>
            <button type="button" class="btn btn-default btn-sm" data-hours="720">{{ lang._('30 days') }}</button>
        </div>
        <span id="probes-totals" class="probes-totals"></span>
        <span id="probes-note" class="probes-note"></span>
    </div>
    <div class="probes-section">
        <div style="height: 200px"><canvas id="probes-chart"></canvas></div>
    </div>
    <p class="probes-note" style="padding: 0 15px">{{ lang._('Packets blocked coming in on the WAN by rules that log (the default deny rule does, unless turned off), except late replies to your own connections.') }}</p>
</div>

<ul class="nav nav-tabs" data-tabs="tabs" style="margin-top: 15px">
    <li class="active"><a data-toggle="tab" href="#probes-tab-sources">{{ lang._('Sources') }}</a></li>
    <li><a data-toggle="tab" href="#probes-tab-ports">{{ lang._('Ports') }}</a></li>
    <li><a data-toggle="tab" href="#probes-tab-map">{{ lang._('Map') }}</a></li>
</ul>
<div class="tab-content content-box">
    <div id="probes-tab-sources" class="tab-pane fade in active">
        <div id="probes-countrypick" class="btn-group" style="display: none">
            <select id="probes-country" data-live-search="true" data-width="180px" data-size="15"
                    title="{{ lang._('All countries') }}"></select>
        </div>
        <table id="grid-sources" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
            <tr>
                <th data-column-id="ip" data-identifier="true" data-formatter="ip">{{ lang._('Source') }}</th>
                <th data-column-id="country" data-formatter="country">{{ lang._('Country') }}</th>
                <th data-column-id="packets" data-formatter="num" data-width="8em">{{ lang._('Packets') }}</th>
                <th data-column-id="ports" data-formatter="num" data-width="7em">{{ lang._('Ports') }}</th>
                <th data-column-id="top" data-formatter="top" data-sortable="false">{{ lang._('Mostly') }}</th>
                <th data-column-id="first" data-formatter="ago" data-width="9em" data-visible="false">{{ lang._('First seen') }}</th>
                <th data-column-id="last" data-formatter="ago" data-width="9em">{{ lang._('Last seen') }}</th>
            </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
    <div id="probes-tab-ports" class="tab-pane fade">
        <table id="grid-ports" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
            <tr>
                <th data-column-id="id" data-identifier="true" data-visible="false">ID</th>
                <th data-column-id="port" data-formatter="port">{{ lang._('Port') }}</th>
                <th data-column-id="service" data-formatter="service">{{ lang._('Service') }}</th>
                <th data-column-id="packets" data-formatter="num" data-width="8em">{{ lang._('Packets') }}</th>
                <th data-column-id="sources" data-formatter="num" data-width="8em">{{ lang._('Sources') }}</th>
            </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
    <div id="probes-tab-map" class="tab-pane fade">
        <div class="probes-section row" style="margin: 0; padding-top: 5px">
            <div class="col-md-8" style="padding-left: 0">
                <div id="probes-map" class="probes-map" style="margin-top: 10px"></div>
                <div id="probes-legend" class="probes-legend"></div>
            </div>
            <div class="col-md-4" style="padding-right: 0">
                <h3>{{ lang._('Countries') }}</h3>
                <table id="probes-countries" class="table table-condensed table-hover probes-countries">
                    <thead><tr><th>{{ lang._('Country') }}</th><th class="text-right">{{ lang._('Packets') }}</th><th class="text-right">{{ lang._('Sources') }}</th></tr></thead>
                    <tbody></tbody>
                </table>
                <p class="probes-note">{{ lang._('Click a country to list its sources.') }}</p>
            </div>
        </div>
    </div>
</div>
