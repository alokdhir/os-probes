# os-probes

An OPNsense plugin that graphs the packets blocked coming in on each WAN interface, as two lines, in **Reporting ▸ Health ▸ Probes** and in a dashboard widget.

- **all**: every packet blocked coming in on that interface. This is the counter behind the "in block" series on Health's Packets graph, shown here for comparison.
- **blocklist**: the packets blocked by blocklist rules. A blocklist rule is an enabled block or reject rule, inbound (or both directions), on that interface (or floating), whose source is an alias filled from a URL: type URL, URL Table or URL Table (JSON). For example, [Spamhaus DROP](https://docs.opnsense.org/manual/how-tos/drop.html) loaded into a URL Table alias.

The blocklist line is part of the "all" line, so the gap between the two is what the blocklists didn't catch.

A WAN is any enabled interface with a gateway set, or an address obtained from the provider (DHCP, DHCPv6, PPPoE and the like). Each WAN gets its own graph.

The plugin has no settings and no page of its own. It adds a collector and a graph type to Health, and Health's own cron job runs them every minute; and a small API (`/api/probes/report/top`) for the widget's lists. Health keeps the history: per minute for 20 hours, per 5 minutes for 60 hours, hourly for 77 days and daily for about 6 years. The graph shows packets per minute.

The **Probes** dashboard widget shows the last 24 hours from Health's 5-minute history: both lines as filled areas, the day's totals and the peak rate, with several WANs added together. Hover for the rate at any time.

Under the graph, two lists from the last 24 hours of the firewall log:

- **Top ports**: the ports (or protocols, such as ICMP) with the most packets blocked coming in on a WAN, with the service's name and how many sources tried them.
- **Top sources**: the addresses with the most packets blocked, how many ports each tried and the one it tried most, tagged **blocklist** when a blocklist rule blocked it.

The lists only see rules that log. OPNsense's default deny rule logs unless "Log packets that are blocked by the default rule" is turned off, so the lists usually cover most of the "all" line, but not all of it. They read the last two days of `/var/log/filter/` (about a second for a million lines); configd keeps the answer for a minute.

## How it counts

Both lines are pf's own running totals, turned into rates by the graph (RRD `DERIVE`):

- **all**: `in4_block_packets` + `in6_block_packets` for the interface, from OPNsense's `scripts/filter/pfstatistics.py interfaces`.
- **blocklist**: the packet counters of the blocklist rules, from OPNsense's `scripts/filter/rule_stats.py`.

pf resets a rule's counters every time the rules are reloaded (when you apply a firewall change, for example). The graph records that minute as unknown, so a reset shows as a one-minute gap in the blocklist line, not a spike or a dip.

Most blocked packets are port scans and login attempts. A few are not: late packets from connections that have already closed, and peer-to-peer VPNs (NetBird, Tailscale) trying a port the router didn't open for them, which is how they look for a direct path.

## Install

From a package repository that carries it (`os-probes`), or for development, from this repository over SSH:

```sh
ROUTER=root@192.168.1.1 tools/deploy.sh              # install or update
ROUTER=root@192.168.1.1 tools/deploy.sh uninstall    # remove
```

Removing the plugin keeps the graph's history in `/var/db/rrd/<interface>-probes.rrd`; delete those files to remove the graph from Health too.

## Caveats

- The collector and graph type plug into Health's internal classes (`scripts/health/library/OPNsense/RRD`), which aren't a documented plugin API. An OPNsense update that changes them could stop this graph until the plugin is updated; nothing else is affected.
- Only rules made in the current firewall rules (Firewall ▸ Rules, the MVC rules, labelled by UUID in pf) are counted on the blocklist line; legacy rules are not.

## License

BSD 2-Clause, see [LICENSE](LICENSE).
