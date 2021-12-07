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

        public override void WriteLine (string message)
        {
            if (string.IsNullOrEmpty (message) || !_colors.TryGetValue (message.Substring (0, 6), out ConsoleColor color))
                color = ConsoleColor.Gray;

            lock (_lockobj)
            {
                Console.ForegroundColor = color;
                base.WriteLine (message);
            }
        }

        static readonly Dictionary<string, ConsoleColor> _colors = new Dictionary<string, ConsoleColor> (StringComparer.InvariantCultureIgnoreCase) {
            { "INFO  ", ConsoleColor.White },
            { "NOTICE", ConsoleColor.DarkGreen },
            { "WARN  ", ConsoleColor.DarkYellow },
            { "ERROR ", ConsoleColor.DarkRed },
        };

        static readonly object _lockobj = new object ();
    }
}
