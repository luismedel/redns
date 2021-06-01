/**
 * 
 * This file is part of redns. A simple, regex-ready and scriptable
 * authoritatibe DNS server for toying, testing and red teaming.
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
    enum MessageOpcode : int
    {
        Query = 0,
        IQuery = 1,
        Status = 2,
        Notify = 4,
        Update = 5,
        DSO = 6
    }
}
