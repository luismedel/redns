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

using System.Collections.Generic;
using System.Linq;
using redns.Protocol.ResourceRecords;

namespace redns.Protocol.Records
{
    class GroupRecord
        : RecordBase
    {
        public List<RecordBase> Records { get; private set; } = new List<RecordBase> ();

        public GroupRecord (Zone zone, string name, RecordClass @class, RecordType type, uint ttl, IEnumerable<RecordBase> records)
            : base (zone, name, @class, type, ttl)
        {
            this.Records.AddRange (records);
        }

        public override IEnumerable<ResourceRecordBase> GetResourceRecordsForQuery (Query query) => Records.SelectMany (record => record.GetResourceRecordsForQuery (query));
    }
}
