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

// Last 24 hours of packets blocked coming in on the WAN(s), from os-probes' database (the firewall log): all of
// them, and those blocked by blocklist rules, with the ports and sources blocked most.
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
        return r ? Probes.esc(r.port !== null && r.port !== undefined ? `${r.proto}/${r.port}` : r.proto) : '';
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
        const d = await this.ajaxCall('/api/probes/report/summary/24');
        if (!d || d.error) {
            $('#probes-w-note').text(this.translations.nodata);
            return;
        }
        if (!this.dataChanged('probes', d)) {
            return;
        }
        this.updateChart(d);
        this.updateTop(d);
    }

    // the last 24 hours in 5-minute steps: all blocked packets, and those blocked by blocklist rules
    updateChart(d) {
        const perMin = d.step / 60;
        $('#probes-w-total').html(
            `<span class="pw-key" style="background:${this.colors.all[0]}"></span>${Probes.count(d.packets)} ${this.translations.blocked}`
            + ` &nbsp;<span class="pw-key" style="background:${this.colors.blocklist[0]}"></span>${Probes.count(d.listed)} ${this.translations.bylists}`);
        $('#probes-w-note').text(d.data_since && d.data_since > d.since + 3600 ? this.translations.since + ' '
            + new Date(d.data_since * 1000).toLocaleString([], {weekday: 'short', hour: 'numeric', minute: '2-digit'}) : '');
        this.chart.data.labels = d.series.map(r => r[0] * 1000);
        this.chart.data.datasets.forEach(ds => {
            ds.data = d.series.map(r => (ds.key === 'all' ? r[1] : r[2]) / perMin);
        });
        const peak = Math.max(0, ...this.chart.data.datasets.flatMap(ds => ds.data));
        $('#probes-w-peak').text(`${this.translations.peak} ${peak.toFixed(peak < 10 ? 1 : 0)}${this.translations.min}`);
        this.chart.update();
    }

    // the ports and sources with the most blocked packets
    updateTop(d) {
        if (!d.packets) {
            $('#probes-w-top').html(`<div class="pw-sub" style="margin-top: 8px">${this.translations.nolog}</div>`);
            return;
        }
        // each links to the page: a port to the sources that tried it, a source to its detail
        const link = (kind, value, text) => `<a href="/ui/probes/#${kind}=${encodeURIComponent(value)}">${text}</a>`;
        const portName = r => r.port !== null && r.port !== undefined ? `${r.proto}/${r.port}` : r.proto;
        const ports = d.ports.map(r => this.row(
            link('port', portName(r), r.service ? `${Probes.esc(r.service)} <span class="pw-sub">${Probes.port(r)}</span>` : Probes.port(r)),
            `${Probes.count(r.sources)} ${r.sources === 1 ? this.translations.source : this.translations.sources}`,
            Probes.count(r.packets)));
        const sources = d.top_sources.map(r => this.row(
            link('source', r.ip, Probes.esc(r.ip)) + (r.country ? ` <span class="pw-sub">${Probes.esc(r.country)}</span>` : '')
                + (r.blocklist ? `<span class="pw-tag" style="background:${this.colors.blocklist[0]}">${this.translations.listed}</span>` : ''),
            `${Probes.count(r.ports)} ${r.ports === 1 ? this.translations.port : this.translations.ports} · ${this.translations.mostly} ${Probes.port(r.top)}`,
            Probes.count(r.packets)));
        $('#probes-w-top').html(
            `<div class="pw-cols">`
            + `<div><div class="pw-title">${this.translations.topports}</div>${ports.join('')}</div>`
            + `<div><div class="pw-title">${this.translations.topsources}</div>${sources.join('')}</div>`
            + `</div>`);
    }

    onWidgetClose() {
        if (this.chart) this.chart.destroy();
    }
}
