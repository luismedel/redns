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
    class TXTResourceRecord
        : ResourceRecord<string>
    {
        public override int Size => this.Data.Length + 1;
        public override RecordType Type => RecordType.TXT;

        public override void Deserialize (MessageStream s, int size)
        {
            this.Data = s.ReadPrefixedString ();
        }

        public override void Serialize (MessageStream s)
        {
            s.WritePrefixedString (this.Data, 255);
        }

        public override void ParseData (object data)
        {
            if (data is string s)
                this.Data = s;
            else if (data is string[] array)
                this.Data = array[0];
            else
                throw new InvalidDataException ($"Invalid TXT data '{data.ToString ()}'");
        }
    }
}
