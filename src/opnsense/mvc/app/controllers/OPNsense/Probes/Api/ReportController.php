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

namespace OPNsense\Probes\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Packets blocked coming in on a WAN, from the collector's database (scripts/probes/query.py). configd keeps
 * each answer for a minute.
 */
class ReportController extends ApiControllerBase
{
    private const SORT = [
        'ports' => ['port', 'service', 'packets', 'sources'],
        'sources' => ['ip', 'country', 'packets', 'ports', 'listed', 'last', 'first'],
    ];

    private function query(array $args)
    {
        $data = json_decode((new Backend())->configdpRun('probes query', $args) ?? '', true);
        return is_array($data) ? $data : ['error' => 'no response'];
    }

    private function hours($hours)
    {
        $hours = (int)$hours;
        return ($hours >= 1 && $hours <= 720) ? (string)$hours : '24';
    }

    /* totals, the graph, countries, and the top 5 ports and sources (the widget uses this too) */
    public function summaryAction($hours = 24)
    {
        return $this->query(['summary', $this->hours($hours)]);
    }

    /* one source: country, first and last seen, the ports it tried, packets per hour */
    public function sourceAction($ip = '', $hours = 24)
    {
        $ip = rawurldecode($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return ['error' => 'not an address'];
        }
        return $this->query(['source', $ip, $this->hours($hours)]);
    }

    public function searchPortsAction()
    {
        return $this->grid('ports');
    }

    public function searchSourcesAction()
    {
        return $this->grid('sources');
    }

    /* a grid page (UIBootgrid): sorting, paging and searching happen in the database */
    private function grid($kind)
    {
        $current = max(1, (int)$this->request->getPost('current', null, 1));
        $count = (int)$this->request->getPost('rowCount', null, 25);
        $count = ($count < 1 || $count > 500) ? 25 : $count;
        $sort = 'packets';
        $dir = 'desc';
        $sorting = $this->request->getPost('sort');
        if (is_array($sorting) && !empty($sorting)) {
            $col = (string)array_key_first($sorting);
            if (in_array($col, self::SORT[$kind], true)) {
                $sort = $col;
                $dir = strtolower((string)$sorting[$col]) === 'asc' ? 'asc' : 'desc';
            }
        }
        $search = preg_replace('/[^A-Za-z0-9.:,_ -]/', '', (string)$this->request->getPost('searchPhrase', null, ''));
        $country = (string)$this->request->getPost('country', null, '');
        if ($kind == 'sources' && preg_match('/^[A-Z]{2}$/', $country)) {
            $search = 'cc:' . $country . ' ' . $search;
        }
        $data = $this->query([
            $kind, $this->hours($this->request->getPost('hours', null, 24)), $sort, $dir,
            (string)(($current - 1) * $count), (string)$count, substr($search, 0, 1200)
        ]);
        return [
            'rows' => $data['rows'] ?? [], 'rowCount' => count($data['rows'] ?? []),
            'total' => $data['total'] ?? 0, 'current' => $current,
        ];
    }
}
