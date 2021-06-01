﻿/**
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

namespace redns.Protocol.Exceptions
{
    class InvalidScriptOutput
        : Exception
    {
        public InvalidScriptOutput (string message)
            : base (message)
        {
        }
    }
}
