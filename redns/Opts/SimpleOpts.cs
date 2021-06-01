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
using System.Collections.Generic;
using System.Text;

namespace redns.opts
{
    static class SimpleOpts
    {
        public static string GetOptValue (string[] args, params string[] names)
        {
            for (int i = 0; i < args.Length; i++)
            {
                var opt = args[i];
                if (Array.IndexOf (names, opt) != -1 && i < args.Length - 1)
                    return args[i + 1];
            }

            return null;
        }

        public static IEnumerable<string> GetOptValues (string[] args, params string[] names)
        {
            int i = 0;
            while (i < args.Length)
            {
                var opt = args[i];
                if (Array.IndexOf (names, opt) != -1 && i < args.Length - 1)
                    yield return args[++i];

                i++;
            }
        }

        public static bool ExistsOpt (string[] args, params string[] names)
        {
            for (int i = 0; i < args.Length; i++)
            {
                var opt = args[i];
                if (Array.IndexOf (names, opt) != -1)
                    return true;
            }

            return false;
        }
    }
}
