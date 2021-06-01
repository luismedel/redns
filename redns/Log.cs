

using System.Diagnostics;
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
namespace redns
{
    static class Log
    {
        public const int DebugLevel = 7;
        public const int InfoLevel = 6;
        public const int NoticeLevel = 5;
        public const int WarnLevel = 4;
        public const int ErrorLevel = 3;
        public const int FatalLevel = 2;

        public static int Level { get; set; } = ErrorLevel;

        public static bool CanWriteDebug => Level >= DebugLevel;
        public static bool CanWriteInfo => Level >= InfoLevel;
        public static bool CanWriteNotice => Level >= NoticeLevel;
        public static bool CanWriteWarn => Level >= WarnLevel;
        public static bool CanWriteError => Level >= ErrorLevel;

        [Conditional ("DEBUG")]
        public static void Debug (string message, params object[] args)
        {
            if (!CanWriteDebug)
                return;

            if (string.IsNullOrEmpty (message))
                Trace.WriteLine (string.Empty);
            else if (args.Length == 0)
                Trace.WriteLine (message, "DEBUG ");
            else
                Trace.WriteLine (string.Format (message, args), "DEBUG ");
        }

        public static void Info (string message, params object[] args)
        {
            if (!CanWriteInfo)
                return;

            if (string.IsNullOrEmpty (message))
                Trace.WriteLine (string.Empty);
            else if (args.Length == 0)
                Trace.WriteLine (message, "INFO  ");
            else
                Trace.WriteLine (string.Format (message, args), "INFO  ");
        }

        public static void Notice (string message, params object[] args)
        {
            if (!CanWriteNotice)
                return;

            if (string.IsNullOrEmpty (message))
                Trace.WriteLine (string.Empty);
            else if (args.Length == 0)
                Trace.WriteLine (message, "NOTICE");
            else
                Trace.WriteLine (string.Format (message, args), "NOTICE");
        }

        public static void Warn (string message, params object[] args)
        {
            if (!CanWriteWarn)
                return;

            if (string.IsNullOrEmpty (message))
                Trace.WriteLine (string.Empty);
            else if (args.Length == 0)
                Trace.WriteLine (message, "WARN  ");
            else
                Trace.WriteLine (string.Format (message, args), "WARN  ");
        }

        public static void Error (string message, params object[] args)
        {
            if (!CanWriteError)
                return;

            if (string.IsNullOrEmpty (message))
                Trace.WriteLine (string.Empty);
            else if (args.Length == 0)
                Trace.WriteLine (message, "ERROR ");
            else
                Trace.WriteLine (string.Format (message, args), "ERROR ");
        }

        public static void Fatal (string message, params object[] args)
        {
            if (args.Length == 0)
                Trace.WriteLine (message, "FATAL ");
            else
                Trace.WriteLine (string.Format (message, args), "FATAL ");
        }
    }
}
