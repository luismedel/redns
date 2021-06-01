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

using System.IO;

namespace redns.Protocol.ResourceRecords
{
    abstract class HostnameResourceRecord
        : ResourceRecord<string>
    {
        public override int Size => this.Data.Length + 2;

        public override void Deserialize (MessageStream s, int size)
        {
            this.Data = s.ReadFQName ();
        }

        public override void Serialize (MessageStream s)
        {
            s.WriteFQName (this.Data);
        }

        public override void ParseData (object data)
        {
            if (data is string s)
                this.Data = s;
            else if (data is string[] array)
                this.Data = array[0];
            else
                throw new InvalidDataException ($"Invalid data '{data.ToString ()}'");
        }
    }
}
