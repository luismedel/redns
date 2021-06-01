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
using System.Net;
using System.Net.Sockets;
using redns.Protocol;

namespace redns
{
    class UdpServer : IServer
    {
        public event EventHandler<RequestEventArgs> RequestReceived;

        public ProtocolType Protocol => ProtocolType.Udp;
        public IPAddress Address { get; private set; }
        public int Port { get; private set; }

        public UdpServer (IPAddress address, int port)
        {
            this.Address = address;
            this.Port = port;
        }

        public async void Listen ()
        {
            if (_running)
                return;

            _running = true;

            IPEndPoint endp = new IPEndPoint (Address, Port);
            _listener = new UdpClient (endp);

            while (_running)
            {
                UdpReceiveResult receiveResult;

                try { receiveResult = await _listener.ReceiveAsync (); }
                catch { continue; }

                var request = new Message (receiveResult.RemoteEndPoint);
                using (var stream = new MessageStream (receiveResult.Buffer))
                    request.Deserialize (stream);

                if (Log.CanWriteDebug)
                {
                    Log.Debug (string.Empty);
                    Log.Debug ("Accepting UDP request from {0}.", receiveResult.RemoteEndPoint);
                    Log.Debug (">>> Incoming message dump:" + DebugUtils.Dump (receiveResult.Buffer));
                }

                var e = new RequestEventArgs (receiveResult.RemoteEndPoint, request);
                RequestReceived?.Invoke (this, e);

                if (e.Response != null)
                {
                    if (e.Response.GetRSectionSize () > 512)
                        e.Response.IsTruncated = true;
                    else
                    {
                        var resp = e.Response.GetBuffer (false);

                        if (Log.CanWriteDebug)
                        {
                            Log.Debug ("<<< Outgoing message dump:" + DebugUtils.Dump (resp));
                            Log.Debug (string.Empty);
                        }

                        _listener.Send (resp, resp.Length, receiveResult.RemoteEndPoint);
                    }
                }
            }
        }

        public void Stop ()
        {
            if (!_running)
                return;
            
            _running = false;
            _listener.Close ();
            _listener.Dispose ();
        }

        bool _running = false;
        UdpClient _listener;
    }
}
