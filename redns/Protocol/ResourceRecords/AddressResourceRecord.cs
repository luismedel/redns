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
using System.Net;
using redns.Protocol.Exceptions;

namespace redns.Protocol.ResourceRecords
{
    abstract class AddressResourceRecord
        : ResourceRecord<IPAddress>
    {
        public override int Size => this.Data.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 4 : 16;

        public override void Deserialize (MessageStream s, int size)
        {
            byte[] bytes = new byte[size];
            s.Read (bytes, 0, size);
            this.Data = new IPAddress (bytes);
        }

        public override void Serialize (MessageStream s)
        {
            byte[] bytes = this.Data.GetAddressBytes ();
            s.Write (bytes, 0, bytes.Length);
        }

        public override void ParseData (object data)
        {
            if (data is string s)
                this.Data = IPAddress.Parse (s);
            else if (data is string[] array)
                this.Data = IPAddress.Parse (array[0]);
            else
                throw new InvalidDataException ($"Invalid IP address '{data.ToString ()}'");
        }
    }
}
