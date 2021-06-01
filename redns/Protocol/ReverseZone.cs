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
using System.Linq;
using System.Net;
using System.Net.Sockets;
using redns.Protocol.Records;

namespace redns.Protocol
{
    class ReverseZone
        : Zone
    {
        public string Hostname { get; private set; }

        public ReverseZone (string hostname, IEnumerable<IPAddress> addresses)
        {
            this.Hostname = hostname;
            this.Origin = "in-addr.arpa";

            HashSet<IPAddress> set = new HashSet<IPAddress> ();

            foreach (var addr in addresses)
            {
                if (addr == IPAddress.Any)
                {
                    set.Add (IPAddress.Loopback);
                    foreach (var locaddr in GetLocalAddresses (AddressFamily.InterNetwork))
                        set.Add (locaddr);
                }
                else if (addr == IPAddress.IPv6Any)
                {
                    set.Add (IPAddress.IPv6Loopback);
                    foreach (var locaddr in GetLocalAddresses (AddressFamily.InterNetworkV6))
                        set.Add (locaddr);
                }
                else
                    set.Add (addr);
            }

            foreach (var addr in set)
            {
                var saddr = addr.ToString ();
                var sep = saddr.IndexOf ('.') == -1 ? ':' : '.';
                var name = string.Join (sep, saddr.Split (sep).Reverse ());
                this.AddRecord (new PTRRecord (this, name, RecordClass.IN, 0) { Data = this.Hostname });
            }
        }

        static IEnumerable<IPAddress> GetLocalAddresses (AddressFamily family)
        {
            return Dns.GetHostEntry (Dns.GetHostName ())
                      .AddressList
                      .Where (addr => addr.AddressFamily == family);
        }
    }
}
