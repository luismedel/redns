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
using System.IO;

namespace redns.Protocol.ResourceRecords
{
    class SOAResourceRecord
        : ResourceRecord<SOAInfo>
    {
        public override int Size => this.Data.Hostname.Length + 2
                                  + this.Data.AdminAddress.Length + 2
                                  + 5 * 4;

        public override RecordType Type => RecordType.SOA;

        public override void Deserialize (MessageStream s, int size)
        {
            this.Data = new SOAInfo {
                Hostname = s.ReadFQName (),
                AdminAddress = s.ReadFQName (),
                SerialNumber = s.ReadDWord (),
                SlaveRefreshPeriod = s.ReadDWord (),
                SlaveRetryTime = s.ReadDWord (),
                SlaveExpirationTime = s.ReadDWord (),
                MinimumTTL = s.ReadDWord ()
            };
        }

        public override void Serialize (MessageStream s)
        {
            s.WriteFQName (this.Data.Hostname);
            s.WriteFQName (this.Data.AdminAddress);
            s.WriteDWord (this.Data.SerialNumber);
            s.WriteDWord (this.Data.SlaveRefreshPeriod);
            s.WriteDWord (this.Data.SlaveRetryTime);
            s.WriteDWord (this.Data.SlaveExpirationTime);
            s.WriteDWord (this.Data.MinimumTTL);
        }

        public override void ParseData (object data)
        {
            var s = data as string[];
            if (s == null || s.Length < 7)
                throw new InvalidDataException ($"Invalid SOA data '{data.ToString ()}'");

            this.Data = new SOAInfo {
                Hostname = s[0],
                AdminAddress = s[1],
                SerialNumber = UInt32.Parse (s[2]),
                SlaveRefreshPeriod = UInt32.Parse (s[3]),
                SlaveRetryTime = UInt32.Parse (s[4]),
                SlaveExpirationTime = UInt32.Parse (s[5]),
                MinimumTTL = UInt32.Parse (s[6])
            };
        }
    }
}
