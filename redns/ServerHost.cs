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
using System.Threading.Tasks;
using redns.Protocol;

namespace redns
{
    class ServerHost
    {
        public string Hostname { get; set; }
        public bool Running { get; private set; }

        public List<Zone> Zones { get; } = new List<Zone> ();
        public List<IServer> Servers { get; } = new List<IServer> ();

        public ServerHost (string hostname)
        {
            this.Hostname = hostname;
        }

        public void AddReverseZone ()
        {
            this.Zones.Add (new ReverseZone (this.Hostname, this.Servers.Select (srv => srv.Address)));
        }

        private void RequestReceived (object sender, RequestEventArgs e)
        {
            var req = e.Request;
            var resp = e.Response = req.GetResponse ();

            if (req.Opcode != MessageOpcode.Query)
                resp.RCode = ReturnCode.NotImp;
            else
            {
                try
                {
                    foreach (var query in req.Queries)
                    {
                        bool validZone = false;
                        bool handled = false;

                        foreach (var zone in Zones)
                        {
                            if (!zone.Active || !query.Name.EndsWith (zone.Origin, StringComparison.InvariantCultureIgnoreCase))
                                continue;

                            validZone = true;

                            var record = zone.GetRecordForQuery (query.Name, query.Type, query.Class);
                            if (record == null)
                                continue;

                            handled = true;
                            resp.IsAuthoritative = true;
                            foreach (var rr in record.EvalQuery (query))
                            {
                                Log.Debug ("Adding resource record '{0}' to answer.", rr.Type);
                                var ans = new Answer (query.Name, rr.Type, query.Class, rr);
                                var list = rr.Type == query.Type ? resp.Answers : resp.AdditionalAnswers;
                                list.Add (ans);
                            }

                            break;
                        }

                        if (!validZone)
                        {
                            handled = true;
                            resp.Clear ();
                            resp.RCode = ReturnCode.NXDomain;
                        }

                        if (!handled)
                        {
                            handled = true;
                            resp.Clear ();
                            resp.RCode = ReturnCode.NotZone;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log.Error ("'{0}' processing request #{1}", ex.Message, req.Id);
                    Log.Debug (ex.StackTrace);

                    resp.Clear ();
                    resp.RCode = ReturnCode.ServFail;
                }
            }

            if (resp.RCode != ReturnCode.NoError)
                Log.Debug ("RCode={0} for request #{1}", resp.RCode, req.Id);
        }

        public void Start ()
        {
            if (Running)
                return;

            Running = true;

            Task.Run (() => {
                foreach (var s in Servers)
                {
                    s.RequestReceived += RequestReceived;
                    s.Listen ();
                }
            });
        }

        public void Stop ()
        {
            if (!Running)
                return;

            Running = false;

            foreach (var s in Servers)
            {
                s.Stop ();
                s.RequestReceived -= RequestReceived;
            }
        }
    }
}
