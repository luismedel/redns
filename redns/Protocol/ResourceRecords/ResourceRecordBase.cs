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

using System;
using System.Collections.Generic;
using System.Reflection;

namespace redns.Protocol.ResourceRecords
{
    abstract class ResourceRecordBase
    {
        public abstract int Size { get; }
        public abstract RecordType Type { get; }

        public abstract void Deserialize (MessageStream s, int size);
        public abstract void Serialize (MessageStream s);
        public abstract void ParseData (object data);

        public static ResourceRecordBase Create (RecordType type)
        {
            if (!_constructors.TryGetValue (type, out ConstructorInfo ctor))
                return new GenericResourceRecord ();

            return (ResourceRecordBase) ctor.Invoke (new object[] {});
        }

        static readonly Dictionary<RecordType, ConstructorInfo> _constructors = new Dictionary<RecordType, ConstructorInfo> {
            { RecordType.A, typeof (AResourceRecord).GetConstructor (new Type[] {}) },
            { RecordType.AAAA, typeof (AAAAResourceRecord).GetConstructor (new Type[] {}) },
            { RecordType.SOA, typeof (SOAResourceRecord).GetConstructor (new Type[] {}) },
            { RecordType.NS, typeof (NSResourceRecord).GetConstructor (new Type[] {}) },
            { RecordType.CNAME, typeof (CNAMEResourceRecord).GetConstructor (new Type[] {}) },
            { RecordType.PTR, typeof (PTRResourceRecord).GetConstructor (new Type[] {}) },
            { RecordType.MX, typeof (MXResourceRecord).GetConstructor (new Type[] {}) },
            { RecordType.TXT, typeof (TXTResourceRecord).GetConstructor (new Type[] {}) },
            { RecordType.NULL, typeof (NULLResourceRecord).GetConstructor (new Type[] {}) },
        };
    }
}
