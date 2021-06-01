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

namespace redns.Protocol.ResourceRecords
{
    abstract class ResourceRecord<T>
        : ResourceRecordBase
    {
        public T Data { get; set; }

    }
}
