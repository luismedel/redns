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
using redns.Protocol.Records;

namespace redns.Protocol.ResourceRecords
{
    class NULLResourceRecord
        : ResourceRecord<byte[]>
    {
        public override int Size => this.Data.Length;
        public override RecordType Type => RecordType.NULL;

        public override void Deserialize (MessageStream s, int size)
        {
            byte[] bytes = new byte[size];
            s.Read (bytes, 0, size);
        }

        public override void Serialize (MessageStream s)
        {
            s.Write (this.Data, 0, this.Data.Length);
        }

        public override void ParseData (object data)
        {
            if (data is string s)
                this.Data = NULLRecord.ParseData (s);
            else if (data is string[] array)
                this.Data = NULLRecord.ParseData (array[0]);
            else
                throw new InvalidDataException ($"Invalid NULL data '{data.ToString ()}'");
        }
    }
}
