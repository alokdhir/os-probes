/*
 * Copyright (C) 2026 Alok K. Dhir
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// Last 24 hours of blocked packets coming in on the WAN(s), from Health's 5-minute history of os-probes'
// graph(s): all of them, and those blocked by blocklist rules. Several WANs are added together.
export default class Probes extends BaseWidget {
    constructor() {
        super();
        this.tickTimeout = 60;
        this.chart = null;
    }

    getGridOptions() {
        return {sizeToContent: 650, w: 4, minW: 2};
    }

    getMarkup() {
        return $(`
            <div class="probes-widget" style="padding: 0 10px 10px; text-align: left">
                <style>
                    .probes-widget, .probes-widget * { text-align: left; }
                    .probes-widget .pw-head { display: flex; flex-wrap: wrap; gap: 0 10px; align-items: baseline; margin-top: 5px; }
                    .probes-widget .pw-axis { display: flex; justify-content: space-between; color: #888; font-size: 10px; }
                    .probes-widget .pw-axis span:last-child { text-align: right; }
                    .probes-widget .pw-key { display: inline-block; width: 8px; height: 8px; border-radius: 2px; margin-right: 3px; }
                    .probes-widget .pw-title { font-weight: bold; font-size: 12px; margin: 10px 0 2px; }
                    .probes-widget .pw-row { display: flex; gap: 8px; align-items: flex-start; padding: 4px 0; border-top: 1px solid rgba(128,128,128,0.2); font-size: 12px; }
                    .probes-widget .pw-main { flex: 1; min-width: 0; }
                    .probes-widget .pw-main > div { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
                    .probes-widget .pw-sub { color: #888; font-size: 11px; }
                    .probes-widget .pw-val { white-space: nowrap; }
                    .probes-widget .pw-val, .probes-widget .pw-val * { text-align: right; }
                    .probes-widget .pw-cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0 16px; }
                    .probes-widget .pw-tag { font-size: 10px; padding: 0 4px; border-radius: 3px; margin-left: 4px; color: #fff; }
                </style>
                <div class="pw-head">
                    <strong>${this.translations.last24}</strong>
                    <span id="probes-w-total" style="font-size: 12px; white-space: nowrap"></span>
                    <span id="probes-w-peak" style="font-size: 11px; color: #888; white-space: nowrap; margin-left: auto"></span>
                </div>
                <div class="canvas-container-noaspectratio" style="height: 80px; margin: 6px 0 2px">
                    <canvas id="probes-w-chart"></canvas>
                </div>
                <div class="pw-axis"><span>${this.translations.ago24}</span><span>${this.translations.now}</span></div>
                <div id="probes-w-note" style="font-size: 12px"></div>
                <div id="probes-w-top"></div>
            </div>
        `);
    }

    static count(n) {
        return Math.round(n).toLocaleString();
    }

    static esc(s) {
        // the API's answer arrives HTML-escaped by core (&amp;): decode once, then escape
        const plain = s == null ? '' : String(s).includes('&') ? $('<textarea/>').html(String(s)).text() : String(s);
        return plain.replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'})[c]);
    }

    // tcp/23, or icmp
    static port(r) {
        return Probes.esc(r.port ? `${r.proto}/${r.port}` : r.proto);
    }

    // one entry: text (and a grey second line) on the left, a number on the right
    row(main, sub, val) {
        return `<div class="pw-row"><div class="pw-main"><div>${main}</div>${sub ? `<div class="pw-sub">${sub}</div>` : ''}</div>`
            + `<div class="pw-val">${val}</div></div>`;
    }

    async onMarkupRendered() {
        this.colors = {
            all: ['rgba(54,162,235,1)', 'rgba(54,162,235,0.25)'],
            blocklist: ['rgba(255,99,71,1)', 'rgba(255,99,71,0.45)']
        };
        this.chart = new Chart($('#probes-w-chart')[0].getContext('2d'), {
            type: 'line',
            data: {labels: [], datasets: ['blocklist', 'all'].map(k => ({
                key: k, label: this.translations[k], data: [],
                borderColor: this.colors[k][0], backgroundColor: this.colors[k][1], fill: 'origin'
            }))},
            options: {
                maintainAspectRatio: false, animation: false,
                interaction: {mode: 'index', intersect: false},
                elements: {line: {borderWidth: 1.5, cubicInterpolationMode: 'monotone'}, point: {radius: 0, hoverRadius: 3}},
                plugins: {legend: {display: false}, tooltip: {itemSort: (a, b) => b.datasetIndex - a.datasetIndex, callbacks: {
                    title: items => new Date(this.chart.data.labels[items[0].dataIndex]).toLocaleTimeString([], {hour: 'numeric', minute: '2-digit'}),
                    label: c => `${c.dataset.label}: ${c.raw.toFixed(c.raw < 10 ? 1 : 0)} ${this.translations.permin}`
                }}},
                scales: {
                    x: {ticks: {display: false}, grid: {display: false},
                        border: {display: true, color: 'rgba(128,128,128,0.5)'}},
                    y: {display: false, beginAtZero: true}
                }
            }
        });
    }

    async onWidgetTick() {
        await this.updateChart();
        await this.updateTop();
    }

    // the ports and sources with the most blocked packets, from the firewall log (logged rules only)
    async updateTop() {
        const d = await this.ajaxCall('/api/probes/report/top');
        if (!d || d.error || !this.dataChanged('probes-top', d)) {
            return;
        }
        if (!d.logged) {
            $('#probes-w-top').html(`<div class="pw-sub" style="margin-top: 8px">${this.translations.nolog}</div>`);
            return;
        }
        const ports = d.ports.map(r => this.row(
            (r.service ? `${Probes.esc(r.service)} <span class="pw-sub">${Probes.port(r)}</span>` : Probes.port(r)),
            `${Probes.count(r.sources)} ${r.sources === 1 ? this.translations.source : this.translations.sources}`,
            Probes.count(r.packets)));
        const sources = d.sources.map(r => this.row(
            Probes.esc(r.ip) + (r.blocklist ? `<span class="pw-tag" style="background:${this.colors.blocklist[0]}">${this.translations.listed}</span>` : ''),
            `${Probes.count(r.ports)} ${r.ports === 1 ? this.translations.port : this.translations.ports} · ${this.translations.mostly} ${Probes.port(r.top)}`,
            Probes.count(r.packets)));
        $('#probes-w-top').html(
            `<div class="pw-cols">`
            + `<div><div class="pw-title">${this.translations.topports}</div>${ports.join('')}</div>`
            + `<div><div class="pw-title">${this.translations.topsources}</div>${sources.join('')}</div>`
            + `</div><div class="pw-sub" style="margin-top: 4px">${this.translations.fromlog}</div>`);
    }

    async updateChart() {
        const list = await this.ajaxCall('/api/diagnostics/systemhealth/get_rrd_list');
        const wans = list?.data?.probes || [];
        if (!wans.length) {
            $('#probes-w-note').text(this.translations.nodata);
            return;
        }
        // detail 1: Health's 5-minute history; values are [ms, packets per second]
        const sets = await Promise.all(wans.map(w => this.ajaxCall(`/api/diagnostics/systemhealth/get_system_health/${encodeURIComponent(w)}-probes/1`)));
        if (!this.dataChanged('probes', sets)) {
            return;
        }
        const since = Date.now() - 24 * 3600 * 1000;
        const sums = {all: new Map(), blocklist: new Map()};
        let step = 300;
        for (const s of sets) {
            step = s?.set?.step_size || step;
            for (const ds of s?.set?.data || []) {
                if (!sums[ds.key]) continue;
                for (const [x, y] of ds.values) {
                    if (x >= since && y !== null && !isNaN(y)) {
                        sums[ds.key].set(x, (sums[ds.key].get(x) || 0) + y);
                    }
                }
            }
        }
        const times = [...new Set([...sums.all.keys(), ...sums.blocklist.keys()])].sort((a, b) => a - b);
        if (!times.length) {
            $('#probes-w-note').text(this.translations.nodata);
            return;
        }
        const total = k => [...sums[k].values()].reduce((t, v) => t + v * step, 0);
        $('#probes-w-total').html(
            `<span class="pw-key" style="background:${this.colors.all[0]}"></span>${Probes.count(total('all'))} ${this.translations.blocked}`
            + ` &nbsp;<span class="pw-key" style="background:${this.colors.blocklist[0]}"></span>${Probes.count(total('blocklist'))} ${this.translations.bylists}`);
        $('#probes-w-note').text(times[0] > since + 3600 * 1000 ? this.translations.since + ' '
            + new Date(times[0]).toLocaleString([], {weekday: 'short', hour: 'numeric', minute: '2-digit'}) : '');
        this.chart.data.labels = times;
        this.chart.data.datasets.forEach(ds => {
            ds.data = times.map(t => (sums[ds.key].get(t) || 0) * 60);
        });
        const peak = Math.max(...this.chart.data.datasets.flatMap(ds => ds.data));
        $('#probes-w-peak').text(`${this.translations.peak} ${peak.toFixed(peak < 10 ? 1 : 0)}${this.translations.min}`);
        this.chart.update();
    }

    onWidgetClose() {
        if (this.chart) this.chart.destroy();
    }
}
