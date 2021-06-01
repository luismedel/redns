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
using System.Linq;
using System.Text.RegularExpressions;
using redns.Protocol.ResourceRecords;

namespace redns.Protocol.Records
{
    class NULLRecord
        : Record<byte[]>
    {
        public NULLRecord (Zone zone, string name, RecordClass @class, UInt32 ttl)
            : base (zone, name, @class, RecordType.NULL, ttl)
        {
        }

        public override IEnumerable<ResourceRecordBase> GetResourceRecordsForQuery (Query query)
        {
            yield return new NULLResourceRecord { Data = this.Data };
        }

        public static byte[] ParseData (string data)
        {
            return Regex.Split (data, @"..", RegexOptions.Compiled)
                        .Select (s => (byte) int.Parse (s, System.Globalization.NumberStyles.HexNumber))
                        .ToArray ();
        }
    }
}
