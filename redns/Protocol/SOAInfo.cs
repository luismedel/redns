/**
 * 
 * This file is part of redns. A simple, regex-ready and scriptable
 * authoritative DNS server for toying, testing and red teaming.
 * 
 * Written by Luis Medel, Percibe Information Security.
 * 
 * Copyright 2021, Percibe S.L.
 * https://percibe.net
 * 
 */

using System;

namespace redns.Protocol
{
    class SOAInfo
    {
        public string Hostname { get; set; }
        public string AdminAddress { get; set; }
        public UInt32 SerialNumber { get; set; }
        public UInt32 SlaveRefreshPeriod { get; set; }
        public UInt32 SlaveRetryTime { get; set; }
        public UInt32 SlaveExpirationTime { get; set; }
        public UInt32 MinimumTTL { get; set; }
    }
}
