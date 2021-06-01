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
using redns.Protocol;

namespace redns
{
    class RequestEventArgs : EventArgs
    {
        public IPEndPoint EndPoint { get; private set; }
        public Message Request { get; private set; }
        public Message Response { get; set; }

        public RequestEventArgs (IPEndPoint endpoint, Message request)
        {
            this.EndPoint = endpoint;
            this.Request = request;
            this.Response = (Message) request.GetResponse ();
            this.Response.IsQuery = false;
        }
    }
}
