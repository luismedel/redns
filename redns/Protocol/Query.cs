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
using System.Text;

namespace redns.Protocol
{
    class Query
    {
        public Message Message { get; private set; }

        public string Name { get; set; }
        public RecordType Type { get; set; }
        public RecordClass Class { get; set; }

        public Query (Message msg)
        {
            this.Message = msg;
        }

        public void Deserialize (MessageStream s)
        {
            Name = s.ReadFQName ();
            Type = (RecordType) s.ReadWord ();
            Class = (RecordClass) s.ReadWord ();
        }

        public void Serialize (MessageStream s)
        {
            s.WriteFQName (Name);
            s.WriteWord ((UInt16) Type);
            s.WriteWord ((UInt16) Class);
        }

        public virtual int GetRSectionSize ()
        {
            return Name.Length + 2 + 4;
        }

        public override string ToString ()
        {
            StringBuilder sb = new StringBuilder ();

            sb.AppendLine ($"Name: {Name}");
            sb.AppendLine ($"Type: {Type}");
            sb.AppendLine ($"Class: {Class}");

            return sb.ToString ();
        }
    }
}
