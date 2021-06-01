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

using System.IO;

namespace redns.Protocol.ResourceRecords
{
    class MXResourceRecord
        : ResourceRecord<MXInfo>
    {
        public override int Size => this.Data.Hostname.Length + 2 + 2;
        public override RecordType Type => RecordType.MX;

        public override void Deserialize (MessageStream s, int size)
        {
            this.Data = new MXInfo {
                Preference = s.ReadWord (),
                Hostname = s.ReadFQName ()
            };
        }

        public override void Serialize (MessageStream s)
        {
            s.WriteWord (this.Data.Preference);
            s.WriteFQName (this.Data.Hostname);
        }

        public override void ParseData (object data)
        {
            var s = data as string[];
            if (s == null || s.Length < 2)
                throw new InvalidDataException ($"Invalid MX data '{data.ToString ()}'");

            this.Data = new MXInfo {
                Preference = int.Parse (s[0]),
                Hostname = s[1]
            };
        }
    }
}
