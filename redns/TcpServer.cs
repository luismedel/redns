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
using System.Threading.Tasks;
using redns.Protocol;

namespace redns
{
    class TcpServer : IServer
    {
        public event EventHandler<RequestEventArgs> RequestReceived;

        public ProtocolType Protocol => ProtocolType.Tcp;
        public IPAddress Address { get; private set; }
        public int Port { get; private set; }

        public TcpServer (IPAddress address, int port)
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
            _listener = new TcpListener (endp);
            _listener.Start ();

            while (_running)
            {
                TcpClient remote;

                try { remote = await _listener.AcceptTcpClientAsync (); }
                catch { continue; }

                Log.Debug (string.Empty);
                Log.Debug ("Accepting TCP request from {0}.", remote.Client.RemoteEndPoint);

                while (remote.Connected)
                {
                    Log.Debug ("Waiting for client data...");
                    while (remote.Available == 0)
                        await Task.Delay (125);

                    byte[] bytes;
                    using (var stream = new MessageStream (remote.GetStream ()))
                    {
                        int length = stream.ReadWord ();
                        bytes = new byte[length];
                        stream.Read (bytes, 0, length);

                        Log.Debug ("Received {0} bytes.", bytes.Length);
                    }

                    if (Log.CanWriteDebug)
                        Log.Debug (">>> Incoming message dump: {0}", DebugUtils.Dump (bytes));

                    var request = new Message ((IPEndPoint) remote.Client.RemoteEndPoint);
                    using (var stream = new MessageStream (bytes))
                        request.Deserialize (stream);

                    var args = new RequestEventArgs ((IPEndPoint) remote.Client.RemoteEndPoint, request);
                    try
                    {
                        RequestReceived?.Invoke (this, args);
                    }
                    catch (Exception ex)
                    {
                        Log.Error ($"{ex.Message} at {ex.StackTrace}");

                        args.Response.Clear ();
                        args.Response.RCode = ReturnCode.ServFail;
                    }

                    if (args.Response != null)
                    {
                        var resp = args.Response.GetBuffer (true);
                        await remote.Client.SendAsync (resp, SocketFlags.None);

                        remote.Client.Close ();

                        if (Log.CanWriteDebug)
                            Log.Debug ("<<< Outgoing message dump: {0}", DebugUtils.Dump (resp));
                    }
                }

                Log.Debug ("TCP connection closed by peer.");
                Log.Debug (string.Empty);
            }
        }

        public void Stop ()
        {
            _running = false;
            _listener.Stop ();
        }

        bool _running = false;

        TcpListener _listener;
    }
}
