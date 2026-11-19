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

namespace OPNsense\RRD\Types;

/**
 * One RRD per WAN interface (<interface>-probes.rrd): packets blocked coming in, all of them and those
 * blocked by blocklist rules. DERIVE with a minimum of 0, so a counter that goes back to zero (pf resets a
 * rule's counters whenever the rules are reloaded) leaves one unknown sample, not a spike.
 */
class Probes extends Base
{
    protected int $ds_heartbeat = 120;
    protected int $ds_min = 0;
    protected int $ds_max = 100000000;
    protected static string $stdfilename = '%s-probes.rrd';

    public function __construct(string $filename)
    {
        parent::__construct($filename);
        $this->addDatasets(['all', 'blocklist'], 'DERIVE');
    }

    public static function payloadSplitter(array $payload)
    {
        foreach ($payload as $ifname => $data) {
            yield static::$basedir . sprintf(static::$stdfilename, $ifname) => $data;
        }
    }
}
