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

using redns.Protocol.Exceptions;

namespace redns.Protocol.ResourceRecords
{
    class GenericResourceRecord
        : ResourceRecord<byte[]>
    {
        public override int Size => this.Data.Length;
        public override RecordType Type => RecordType.None;

        public override void Deserialize (MessageStream s, int size)
        {
            byte[] bytes = new byte[size];
            s.Read (bytes, 0, size);
            this.Data = bytes;
        }

        public override void Serialize (MessageStream s)
        {
            s.Write (this.Data, 0, this.Data.Length);
        }

        public override void ParseData (object data)
        {
            throw new YouReNotSupposedToBeHereException ();
        }
    }
}
