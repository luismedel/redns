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
using redns.Protocol;
using redns.Protocol.Exceptions;
using redns.Protocol.Records;

namespace redns
{
    class Zone
    {
        public bool Active { get; private set; } = true;

        public string Origin
        {
            get => _origin;
            set
            {
                _origin = value;
                if (_origin.EndsWith ('.'))
                    _origin = _origin.Substring (0, _origin.Length - 1);
            }
        }

        public UInt32 TTL { get; set; }

        public Zone ()
        { }

        public void AddRecord (RecordBase record)
        {
            var prev = _records.FirstOrDefault (rec => rec.Key == record.Key);
            if (prev != null && prev.IsUnique)
                throw new DuplicateRecordException ($"Duplicated record '{record.Key}'");

            _records.Add (record);
        }

        public RecordBase GetRecordForQuery (string name, RecordType type, RecordClass @class)
        {
            if (!name.EndsWith (Origin, StringComparison.InvariantCultureIgnoreCase))
                return null;

            var recordKey = GetRecordKey (GetFQName (name), @class, type);

            Log.Debug ("Searching a match for '{0}'", recordKey);

            RecordBase result = null;

            if (_cachedRecords.TryGetValue (recordKey, out result))
            {
                Log.Debug ("Returning cached '{0}'", recordKey);
                return result;
            }

            var matches = _records.Where (rec => (type == RecordType.ALL || rec.Type == type)
                                        && (@class == RecordClass.ANY || rec.Class == @class)
                                        && rec.CanAnswerQuery (name))
                                    .ToArray ();

            if (matches.Length == 0)
                _cachedRecords[recordKey] = result = null;
            else
            {
                result = matches.Length == 1 ? matches[0] : new GroupRecord (this, string.Empty, @class, type, this.TTL, matches);

                if (_cachedRecords.Count <= MAX_CACHED_RECORDS)
                {
                    bool isCacheable = !matches.Any (rec => rec.IsScript);
                    if (isCacheable)
                    {
                        Log.Debug ("Adding result to cache");
                        _cachedRecords[recordKey] = result;
                        if (_cachedRecords.Count == MAX_CACHED_RECORDS)
                            Log.Debug ("Max cache size reached ({0})", MAX_CACHED_RECORDS);
                    }
                    else
                        Log.Debug ("Response is not cacheable");
                }
            }

            if (result == null)
                Log.Debug ("Can't find a match for '{0}'", recordKey);

            return result;
        }

        public void DeserializeFromFile (string path)
        {
            this.Active = false;

            _records.Clear ();
            _cachedRecords.Clear ();

            Log.Debug ("Loading zone from file '{0}'", path);

            ZoneFileParser parser;
            using (var s = System.IO.File.OpenRead (path))
                parser = new ZoneFileParser (s);

            parser.Parse (this);

            this.Active = true;
        }

        public string GetFQName (string name)
        {
            if (name.EndsWith ('.'))
                return name.Substring (0, name.Length - 1);
            else if (name.EndsWith (_origin, StringComparison.InvariantCultureIgnoreCase))
                return name;
            else
                return $"{name}.{_origin}";
        }

        internal static string GetRecordKey (string name, RecordClass @class, RecordType type)
        {
            return $"{name}:{@class}:{@type}";
        }

        public static Zone FromFile (string path)
        {
            var result = new Zone ();
            result.DeserializeFromFile (path);
            return result;
        }

        string _origin;

        readonly List<RecordBase> _records = new List<RecordBase> ();
        readonly Dictionary<string, RecordBase> _cachedRecords = new Dictionary<string, RecordBase> (StringComparer.InvariantCultureIgnoreCase);

        const int MAX_CACHED_RECORDS = 1024;
    }
}
