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
using System.Text.RegularExpressions;
using redns.Protocol.ResourceRecords;
using MoonSharp.Interpreter;
using redns.Protocol.Exceptions;

namespace redns.Protocol.Records
{
    abstract class RecordBase
    {
        public Zone Zone { get; private set; }

        public string Key { get; private set; }

        public string FQName { get; private set; }
        public RecordClass Class { get; private set; }
        public RecordType Type { get; private set; }
        public UInt32 TTL
        {
            get => _ttl == 0 ? Zone.TTL : _ttl;
            private set => _ttl = value;
        }

        public bool IsRegex => NameExpr != null;
        public bool IsScript => Script != null;

        public virtual bool IsUnique => true;

        public Regex NameExpr { get; private set; }
        public Script Script { get; private set; }

        public RecordBase (Zone zone, string name, RecordClass @class, RecordType type, UInt32 ttl)
        {
            this.Zone = zone;

            var m = Regex.Match (name, @"^\/[^\/]+\/$");
            if (!m.Success)
                this.FQName = this.Zone.GetFQName (name);
            else
            {
                this.FQName = name; // Preserve pattern in FQName
                this.NameExpr = new Regex (name.Substring (1, name.Length - 2) + Regex.Escape ("." + zone.Origin), RegexOptions.Compiled | RegexOptions.IgnoreCase);
            }
            this.Class = @class;
            this.Type = type;
            this.TTL = ttl;

            this.Key = Zone.GetRecordKey (this.FQName, @class, type);
        }

        public virtual bool CanAnswerQuery (string qname)
        {
            return (this.NameExpr != null) ? this.NameExpr.IsMatch (qname)
                                           : this.FQName.Equals (qname, StringComparison.InvariantCultureIgnoreCase);
        }

        public IEnumerable<ResourceRecordBase> EvalQuery (Query query)
        {
            if (Script != null)
            {
                Log.Info ("Running script for record '{0}'", this.Key);

                Script.Globals["remoteAddress"] = query.Message.RemoteEndPoint.Address.ToString ();
                Script.Globals["remotePort"] = query.Message.RemoteEndPoint.Port.ToString ();

                Script.Globals["requestName"] = query.Name;
                Script.Globals["responseType"] = this.Type.ToString ();

                /**    
                 * Result can be:
                 *  - a string           --> return "192.168.2.1"
                 *  - a table            --> return { 10, "mail.example.com." }
                 *  - a tuple of strings --> return "192.168.2.1", "192.168.2.2"
                 *  - a tuple of tables  --> return { 10, "mail.example.com." }, { 20, "mail2.example.com." }
                 */

                DynValue scriptResult;
                try { scriptResult = Script.Call (_scriptfn); }
                catch (ScriptRuntimeException ex)
                {
                    Log.Error ($"Error '{ex.Message}' running script for record {Key}: {ex.DecoratedMessage}");
                    yield break;
                }

                RecordType responseType = Enum.Parse<RecordType> (Script.Globals.Get ("responseType").String, true);

                if (responseType != query.Type)
                    Log.Info ("Script changed response type from '{0}' to '{1}'", query.Type, responseType);

                foreach (var result in EnumerateScriptResult (scriptResult))
                {
                    var resRecord = ResourceRecordBase.Create (responseType);
                    resRecord.ParseData (result);
                    yield return resRecord;
                }
            }
            else
            {
                foreach (var rr in this.GetResourceRecordsForQuery (query))
                    yield return rr;
            }
        }

        object GetScriptValue (DynValue value)
        {
            if (value.String != null)
                return value.String;
            else if (value.Table != null)
                return value.Table.Values.Select (v => v.ToString ()).ToArray ();
            else
                return null;
        }

        IEnumerable<object> EnumerateScriptResult (DynValue value)
        {
            var result = GetScriptValue (value);
            if (result != null)
                yield return result;
            else if (value.Tuple != null)
            {
                foreach (var o in value.Tuple.Select (v => GetScriptValue (v)))
                    yield return o;
            }
            else
                throw new InvalidScriptOutput ($"Invalid output '{value.ToString ()}'");
        }

        public void SetScript (string script)
        {
            this.Script = new Script (CoreModules.Preset_Default);
            this.Script.DoString ($"function {SCRIPT_FN_NAME} (){Environment.NewLine}{script}{Environment.NewLine}end");
            _scriptfn = Script.Globals.Get (SCRIPT_FN_NAME).Function;
        }

        public abstract IEnumerable<ResourceRecordBase> GetResourceRecordsForQuery (Query query);

        UInt32 _ttl = 0;
        Closure _scriptfn;

        public static RecordBase Create (Zone zone, string name, RecordClass @class, RecordType type, UInt32 ttl)
        {
            RecordBase result = null;

            if (_classes.TryGetValue (type, out Type t))
            {
                var ctor = t.GetConstructor (new Type[] { typeof (Zone), typeof (string), typeof (RecordClass), typeof (UInt32) });
                if (ctor != null)
                    result = (RecordBase) ctor.Invoke (new object[] { zone, name, @class, ttl });
            }

            if (result == null)
            {
                Log.Notice ("Unsupported record type '{0}' of class '{1}'", type, @class);
                result = new GenericRecord (zone, name, @class, type, ttl);
            }

            return result;
        }

        static readonly Dictionary<RecordType, Type> _classes = new Dictionary<RecordType, Type> {
            { RecordType.A, typeof (ARecord) },
            { RecordType.AAAA, typeof (AAAARecord) },
            { RecordType.NS, typeof (NSRecord) },
            { RecordType.PTR, typeof (PTRRecord) },
            { RecordType.CNAME, typeof (CNAMERecord) },
            { RecordType.SOA, typeof (SOARecord) },
            { RecordType.MX, typeof (MXRecord) },
            { RecordType.TXT, typeof (TXTRecord) },
            { RecordType.NULL, typeof (NULLRecord) },
        };

        const string SCRIPT_FN_NAME = "__exec__";
    }
}
