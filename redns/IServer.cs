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
using System.Net;
using System.Net.Sockets;

namespace redns
{
    interface IServer
    {
        event EventHandler<RequestEventArgs> RequestReceived;

        ProtocolType Protocol { get; }
        IPAddress Address { get; }
        int Port { get; }

        void Listen ();
        void Stop ();
    }
}
