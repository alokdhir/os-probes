# os-probes

An OPNsense plugin that shows who is probing your network from the internet: the packets blocked coming in on your WAN, where they came from, and what they tried. It adds a page, **Reporting ▸ Probes**, and a dashboard widget.

## The page

- **A graph** of packets blocked per minute, as two lines: all of them, and those blocked by blocklist rules. Pick the last 24 hours, 7 days or 30 days.
- **Sources**: every address that was blocked, with its country, packets, how many ports it tried, the port it tried most, and when it was first and last seen. Click one for its detail: packets per hour, and each port it tried. Search by address, country code (`CN`) or port (`23`: the sources that tried it).
- **Ports**: every port (or protocol, such as ICMP) that was tried, with the service's name, packets and how many sources tried it. Search by port, service name (`ssh`) or protocol.
- **Map**: a world map shaded by packets per country, beside a list of countries. Click a country to list its sources.

The dashboard widget shows the last 24 hours: the graph, the totals and the peak rate, with the top five ports and sources.

## What it counts

Packets blocked coming in on a WAN, as the firewall log records them. A WAN is any enabled interface with a gateway set, or an address obtained from the provider (DHCP, DHCPv6, PPPoE and the like); several WANs are added together.

The log only records rules that log. OPNsense's default deny rule does, unless "Log packets that are blocked by the default rule" is turned off (Firewall ▸ Settings ▸ Advanced), so in a usual setup this is nearly everything blocked. If it's off, the page has little to show.

A **blocklist** rule is an enabled block or reject rule, inbound (or both directions), on a WAN (or floating), whose source is an alias filled from a URL: type URL, URL Table or URL Table (JSON). For example, [Spamhaus DROP](https://docs.opnsense.org/manual/how-tos/drop.html) loaded into a URL Table alias. Sources a blocklist rule blocked are tagged **blocklist**. Only rules made in Firewall ▸ Rules (the MVC rules, which pf labels with their UUID) are recognised; legacy rules are not.

Most blocked packets are port scans and login attempts. A few are not: late packets from connections that have already closed, and peer-to-peer VPNs (NetBird, Tailscale) trying a port the router didn't open for them, which is how they look for a direct path.

## Countries

Countries come from the GeoIP database that OPNsense downloads for GeoIP aliases. Set it up in **Firewall ▸ Aliases ▸ GeoIP settings**: for example, MaxMind's free GeoLite2 Country (sign up at maxmind.com, create a license key, and use the URL `https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=YOUR_KEY&suffix=zip`). To keep it current, add a job for "Update GeoIP database" in **System ▸ Settings ▸ Cron**; MaxMind publishes twice a week. Without it, the page leaves out the country column and the map.

## How it works

- Every minute a cron job (`configctl probes collect`, from `plugins.inc.d/probes.inc`) reads the firewall log lines written since the last run (`/var/log/filter/`) and adds the blocked packets to hourly totals per source and port, in `/var/db/probes/probes.db`. The first run reads the last 30 days of log, which can take a minute.
- Every 5 minutes it also adds up the totals for each of the page's periods, so the page loads at once. A graph point is 5 minutes for the last 24 hours, an hour for 7 days and 4 hours for 30 days.
- 30 days are kept. The page and widget read the database through `/api/probes/report/*` (configd `probes query`).

The plugin has no settings.

## Install

From a package repository that carries it (`os-probes`), or for development, from this repository over SSH:

```sh
ROUTER=root@192.168.1.1 tools/deploy.sh              # install or update
ROUTER=root@192.168.1.1 tools/deploy.sh uninstall    # remove
```

Removing the plugin keeps its database in `/var/db/probes/`; delete that directory to remove it too.

## License

BSD 2-Clause, see [LICENSE](LICENSE). The world map is [Natural Earth](https://www.naturalearthdata.com/) (public domain), reduced; see `src/opnsense/www/js/probes/world.json.LICENSE`.
