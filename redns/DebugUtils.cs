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

using System.Text;

namespace redns
{
    static class DebugUtils
    {
        public static string Dump (byte[] data, string indentation="", bool printOffset=true, int colSize=16, int colSep=8, bool showNulls=true)
        {
            indentation = indentation ?? string.Empty;

            StringBuilder sb = new StringBuilder ();

            for (int i = 0; i < data.Length; i++)
            {
                if (i % colSize == 0)
                {
                    sb.AppendLine ();
                    sb.Append (indentation);
                    sb.Append (i.ToString ("x4"));
                    sb.Append ("  ");
                }
                else if (i % colSep == 0)
                    sb.Append (' ');

                byte b = data[i];
                if (b != 0 || showNulls)
                    sb.Append ((b != 0 || showNulls) ? b.ToString ("x2"): "  ");

                sb.Append (' ');
            }

            return sb.ToString ();
        }
    }
}
