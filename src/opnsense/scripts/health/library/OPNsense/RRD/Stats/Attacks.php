<?php

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

namespace OPNsense\RRD\Stats;

use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;
use OPNsense\Firewall\Filter;

/**
 * Packets blocked coming in on each WAN interface: all of them, and those blocked by rules whose source is a
 * blocklist (an alias filled from a URL). Both are pf's running totals; the RRD turns them into rates.
 */
class Attacks extends Base
{
    /* alias types whose content is downloaded: what makes an alias a blocklist */
    private const LIST_TYPES = ['url', 'urltable', 'urljson'];

    /* how an interface gets its upstream address: any of these makes it a WAN */
    private const DYNAMIC = ['dhcp', 'dhcp6', 'pppoe', 'pptp', 'l2tp', 'slaac', '6rd', '6to4'];

    public function run()
    {
        $wans = $this->wanInterfaces();
        if (empty($wans)) {
            return [];
        }
        $ifstats = $this->jsonShellCmd('/usr/local/opnsense/scripts/filter/pfstatistics.py interfaces');
        $rulestats = $this->jsonShellCmd('/usr/local/opnsense/scripts/filter/rule_stats.py');
        if (empty($ifstats['interfaces'])) {
            return [];
        }
        $rules = $this->blocklistRules(array_keys($wans));

        $result = [];
        foreach ($wans as $ifname => $device) {
            $counts = $ifstats['interfaces'][$device] ?? null;
            if ($counts === null) {
                continue;
            }
            $blocklist = 0;
            foreach ($rules[$ifname] as $uuid) {
                $blocklist += $rulestats[$uuid]['packets'] ?? 0;
            }
            $result[$ifname] = [
                'all' => ($counts['in4_block_packets'] ?? 0) + ($counts['in6_block_packets'] ?? 0),
                'blocklist' => $blocklist,
            ];
        }
        return $result;
    }

    /**
     * enabled interfaces that face upstream: a gateway set, or an address obtained from the provider
     * @return array OPNsense interface name => device, e.g. ['wan' => 'igc0']
     */
    private function wanInterfaces()
    {
        $result = [];
        foreach (Config::getInstance()->object()->interfaces->children() as $ifname => $node) {
            if (!isset($node->enable) || empty((string)$node->if)) {
                continue;
            }
            if (
                !empty((string)$node->gateway) || !empty((string)$node->gatewayv6) ||
                in_array((string)$node->ipaddr, self::DYNAMIC) || in_array((string)$node->ipaddrv6, self::DYNAMIC)
            ) {
                $result[$ifname] = (string)$node->if;
            }
        }
        return $result;
    }

    /**
     * enabled block/reject rules on the given interfaces, inbound, whose source is a blocklist alias
     * @param array $ifnames interface names
     * @return array interface name => [rule uuid, ...] (pf labels these rules with their uuid)
     */
    private function blocklistRules(array $ifnames)
    {
        $lists = [];
        foreach ((new Alias())->aliases->alias->iterateItems() as $alias) {
            if ((string)$alias->enabled == '1' && in_array((string)$alias->type, self::LIST_TYPES)) {
                $lists[(string)$alias->name] = true;
            }
        }

        $result = array_fill_keys($ifnames, []);
        if (empty($lists)) {
            return $result;
        }
        foreach ((new Filter())->rules->rule->iterateItems() as $uuid => $rule) {
            if (
                (string)$rule->enabled != '1' || !in_array((string)$rule->action, ['block', 'reject']) ||
                (string)$rule->direction == 'out' || (string)$rule->source_not == '1'
            ) {
                continue;
            }
            $sources = array_filter(explode(',', (string)$rule->source_net));
            if (empty(array_intersect_key(array_flip($sources), $lists))) {
                continue;
            }
            /* no interface means a floating rule on every interface; "not" inverts the list */
            $listed = array_filter(explode(',', (string)$rule->interface));
            $invert = (string)$rule->interfacenot == '1';
            foreach ($ifnames as $ifname) {
                if (empty($listed) || (in_array($ifname, $listed) != $invert)) {
                    $result[$ifname][] = $uuid;
                }
            }
        }
        return $result;
    }
}
