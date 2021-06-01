﻿/**
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

namespace redns.Protocol
{
    /// <summary>
    /// From https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
    /// </summary>
    enum ReturnCode : int
    {
        NoError = 0,            // No Error 	[RFC1035]
        FormErr = 1,            // Format Error 	[RFC1035]
        ServFail = 2,           // Server Failure 	[RFC1035]
        NXDomain = 3,           // Non-Existent Domain 	[RFC1035]
        NotImp = 4,             // Not Implemented 	[RFC1035]
        Refused = 5,            // Query Refused 	[RFC1035]
        YXDomain = 6,           // Name Exists when it should not 	[RFC2136][RFC6672]
        YXRRSet = 7,            // RR Set Exists when it should not 	[RFC2136]
        NXRRSet = 8,            // RR Set that should exist does not 	[RFC2136]
        NotAuth = 9,            // Not Authorized 	[RFC8945]
        NotZone = 10,           // Name not contained in zone 	[RFC2136]
        DSOTYPENI = 11,         // DSO-TYPE Not Implemented 	[RFC8490]
        BADVERS = 16,           // Bad OPT Version 	[RFC6891]
        BADSIG = 16,            // TSIG Signature Failure 	[RFC8945]
        BADKEY = 17,            // Key not recognized 	[RFC8945]
        BADTIME = 18,           // Signature out of time window 	[RFC8945]
        BADMODE = 19,           // Bad TKEY Mode 	[RFC2930]
        BADNAME = 20,           // Duplicate key name 	[RFC2930]
        BADALG = 21,            // Algorithm not supported 	[RFC2930]
        BADTRUNC = 22,          // Bad Truncation 	[RFC8945]
        BADCOOKIE = 23,			// Bad/missing Server Cookie 	[RFC7873]
    }
}
