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
using System.Collections.Generic;
using System.Text;
using redns.Protocol.ResourceRecords;

namespace redns.Protocol.Records
{
    class GenericRecord
        : Record<string>
    {
        public GenericRecord (Zone zone, string name, RecordClass @class, RecordType type, UInt32 ttl)
            : base (zone, name, @class, type, ttl)
        { }

        public override IEnumerable<ResourceRecordBase> GetResourceRecordsForQuery (Query query)
        {
            yield return new GenericResourceRecord { Data = Encoding.ASCII.GetBytes (this.Data) };
        }
    }
}
