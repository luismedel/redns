using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace redns
{
    class ConsoleTraceListener
        : TextWriterTraceListener
    {
        public ConsoleTraceListener ()
            : base (Console.Out)
        {
        }
    }
}
