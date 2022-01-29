/**
 *                   __          
 *    ________  ____/ /___  _____
 *   / ___/ _ \/ __  / __ \/ ___/
 *  / /  /  __/ /_/ / / / (__  ) 
 * /_/   \___/\__,_/_/ /_/____/ 
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
using System.Linq;
using System.Net;
using System.Threading;
using redns.opts;

namespace redns
{
    class Program
    {
        static string VERSION = "0.9";

        static void ShowUsage (string message = null)
        {
            if (!string.IsNullOrEmpty (message))
            {
                Console.WriteLine (message);
                Console.WriteLine ();
            }

            Console.WriteLine (@"

redns - A simple, regex-ready and scriptable authoritative DNS server for
        toying, testing and red teaming

Usage:

  redns [options]

Where options can be:

 --zone <path>                 Loads zone from file (defaults to ./zone.conf)
                               (can be used multiple times)

 --no-reverse-zone             Don't automatically a reverse zone.

 --bind <proto>:<addr>:<port>  Listens at the specified endpoint, where:
                                    <proto>  udp|tcp.
                                    <addr>   local address to bind to.
                                    <port>   local port to bind to.
                               (can be used multiple times)

 --log <path>                  Send logs to file.
 --no-console                  Disables console output.
 --loglevel <level>            debug|info|warn|error|all (defaults to debug).

 --help                        Prints this screen and exit.

Call redns without arguments to start the default server:

  redns --zone .\zone.conf \
        --bind udp:0.0.0.0:5553 \
        --bind tcp:0.0.0.0:5553 \
        --loglevel debug
");
        }

        static void Main (string[] args)
        {
            bool writeToConsole = true;

            Log.Level = Log.DebugLevel;

            var host = new ServerHost (Dns.GetHostName ());
            if (SimpleOpts.ExistsOpt (args, "--hostname"))
                host.Hostname = SimpleOpts.GetOptValue (args, "--hostname");

            if (!SimpleOpts.ExistsOpt (args, "--nobanner"))
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine ($@"
                  __          
   ________  ____/ /___  _____
  / ___/ _ \/ __  / __ \/ ___/
 / /  /  __/ /_/ / / / (__  ) 
/_/   \___/\__,_/_/ /_/____/  v{VERSION}
");
                Console.ForegroundColor = ConsoleColor.Gray;
            }

            if (args.Length == 0)
            {
                System.Diagnostics.Trace.Listeners.Add (new ConsoleTraceListener ());
                Log.Info ("Starting default server...");

                host.Zones.Add (Zone.FromFile (@"zone.conf"));

                host.Servers.Add (new UdpServer (IPAddress.Any, 5553));
                host.Servers.Add (new TcpServer (IPAddress.Any, 5553));
            }
            else
            { 
                if (SimpleOpts.ExistsOpt (args, "--help"))
                {
                    ShowUsage ();
                    return;
                }

                if (SimpleOpts.ExistsOpt (args, "--no-console"))
                    writeToConsole = false;
                else
                    System.Diagnostics.Trace.Listeners.Add (new System.Diagnostics.TextWriterTraceListener (Console.Out));

                var logFile = SimpleOpts.GetOptValue (args, "--log");
                if (!string.IsNullOrEmpty (logFile))
                    System.Diagnostics.Trace.Listeners.Add (new System.Diagnostics.TextWriterTraceListener (logFile));


                host.Zones.AddRange (SimpleOpts.GetOptValues (args, "--zone")
                                               .Select (path => Zone.FromFile (path)));

                foreach (var opt in SimpleOpts.GetOptValues (args, "--bind"))
                {
                    var parts = opt.Split (new char[] { ':' }, 3);
                    var proto = parts[0];
                    var addr = parts[1];

                    if (!int.TryParse (parts[2], out int port))
                    {
                        Log.Fatal ($"Invalid port '{parts[2]}'.");
                        return;
                    }

                    if (proto.Equals ("udp", StringComparison.InvariantCultureIgnoreCase))
                        host.Servers.Add (new UdpServer (IPAddress.Parse (addr), port));
                    else if (proto.Equals ("tcp", StringComparison.InvariantCultureIgnoreCase))
                        host.Servers.Add (new TcpServer (IPAddress.Parse (addr), port));
                    else
                    {
                        Log.Fatal ($"Invalid protocol '{proto}'.");
                        return;
                    }
                }
            }

            if (!SimpleOpts.ExistsOpt (args, "--no-reverse-zone"))
                host.AddReverseZone ();

            if (host.Zones.Count == 0)
            {
                Log.Fatal ("No zones to serve");
                ShowUsage ("Specify at least one zone file");
                return;
            }

            if (host.Servers.Count == 0)
            {
                Log.Fatal ("No servers specified");
                ShowUsage ("Specify at least one endpoint");
                return;
            }

            host.Start ();

            foreach (var z in host.Zones)
                Log.Info ($"Serving requests for zone '{z.Origin}'.");

            foreach (var s in host.Servers)
                Log.Info ($"Listening on {s.Protocol} {s.Address}:{s.Port}...");

            using (ManualResetEvent resetEvt = new ManualResetEvent (false))
            {
                bool exitHandled = false;

                if (writeToConsole)
                {
                    Console.WriteLine ("Press Ctrl+C to stop.");

                    Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e) {
                        if (exitHandled)
                            return;
                        exitHandled = true;

                        Log.Notice ("Received Ctrl+C.");
                        resetEvt.Set ();
                        e.Cancel = true;
                    };
                }

                AppDomain.CurrentDomain.ProcessExit += (sender, e) => {
                    Log.Info ("Exiting...");
                    if (!exitHandled)
                    {
                        exitHandled = true;
                        resetEvt.Set ();
                    }
                };

                resetEvt.WaitOne ();
            }

            host.Stop ();
        }
    }
}
