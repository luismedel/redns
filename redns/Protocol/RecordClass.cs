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
    /// <summary>
    /// From https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
    /// </summary>
    enum RecordClass : UInt16
    {
        Reserved = 0,   // [RFC6895]
        IN = 1,         // [RFC1035]
        CH = 3,         // [D. Moon, "Chaosnet", A.I. Memo 628, Massachusetts Institute of Technology Artificial Intelligence Laboratory, June 1981.]
        HS = 4,         // [Dyer, S., and F. Hsu, "Hesiod", Project Athena Technical Plan - Name Service, April 1987.]
        NONE = 254,     // [RFC2136]
        ANY = 255,		// [RFC1035]
    }
}
