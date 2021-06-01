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
using redns.Protocol.Records;
using redns.Protocol.ResourceRecords;

namespace redns.Protocol
{
    class Answer
    {
        public string Name { get; set; }
        public RecordType Type { get; set; }
        public RecordClass Class { get; set; }
        public UInt32 TTL { get; set; }
        public ResourceRecordBase ResourceRecord { get; private set; }

        //public List<ResourceRecordBase> ResourceRecords { get; private set; } = new List<ResourceRecordBase> ();

        public RecordBase Record
        {
            get => _record;
            set {
                _record = value;
                this.TTL = _record.TTL;
            }
        }

        public Answer (string name, RecordType type, RecordClass @class, ResourceRecordBase rr)
        {
            this.Name = name;
            this.Type = type;
            this.Class = @class;
            this.ResourceRecord = rr;
        }

        public void Serialize (MessageStream s)
        {
            s.WriteFQName (Name);
            s.WriteWord ((UInt16) Type);
            s.WriteWord ((UInt16) Class);
            s.WriteDWord (TTL);

            s.WriteWord (0); // temp
            long rdataStart = s.Position;
            ResourceRecord.Serialize (s);
            long rdataEnd = s.Position;
            int rdataLength = (int) (rdataEnd - rdataStart);
            s.Seek (rdataStart - 2, System.IO.SeekOrigin.Begin);
            s.WriteWord (rdataLength);
            s.Seek (rdataEnd, System.IO.SeekOrigin.Begin);
        }

        public void Deserialize (MessageStream s)
        {
            this.Name = s.ReadFQName ();
            this.Type = (RecordType) s.ReadWord ();
            this.Class = (RecordClass) s.ReadWord ();
            this.TTL = s.ReadDWord ();

            int size = s.ReadWord ();
            this.ResourceRecord.Deserialize (s, size);
        }

        public virtual int GetRSectionSize () => Name.Length + 2 + 4 + 4 + this.ResourceRecord.Size;

        RecordBase _record = null;
    }
}