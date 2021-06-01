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
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using redns.Protocol;
using redns.Protocol.Exceptions;
using redns.Protocol.Records;

namespace redns
{
    /**
     * I've spent too much time writing parsers lately.
     * I should extract this mess as a proper parsing framework and stop repeating myself.
     * -- Luis
     */
    class ZoneFileParser
    {
        public ZoneFileParser (Stream stream)
        {
            using (StreamReader sr = new StreamReader (stream))
                _input = sr.ReadToEnd ();

            var tk = _fileTokenizer.Tokenize (_input).ToList ();
            tk.Add (new Token (TokenType.EOL, "\n", -1));
            tk.Add (new Token (TokenType.EOF, string.Empty, -1));
            _reader = new TokenReader (tk);
        }

        public void Parse (Zone zone)
        {
            _zone = zone;
            Parse ();
            _zone = null;
        }

        void Parse ()
        {
            string currentName = string.Empty;

            do
            {
                // Skip empty lines
                while (_reader.Consume (TokenType.EOL))
                    ;

                Token t = _reader.Read ();
                switch (t.Type)
                {
                    case TokenType.Directive:
                        ParseDirective (t.Value);
                        break;

                    case TokenType.NonBlank:
                        {
                            ParseRecord (t.Value == "@" ? this._zone.Origin : t.Value);
                            break;
                        }

                    case TokenType.EOF:
                        break;

                    default:
                        throw new ZoneFileException (t.Line, $"Unexpected input '{t.Value}'");
                }

                if (!_reader.Consume (TokenType.EOL))
                    _reader.Expect (TokenType.EOF);

            } while (_reader.Peek ().Type != TokenType.EOF);
        }

        void ParseDirective (string directive)
        {
            if (directive.Equals ("$ORIGIN", StringComparison.InvariantCultureIgnoreCase))
                _zone.Origin = _reader.Expect (TokenType.NonBlank).Value;
            else if (directive.Equals ("$TTL", StringComparison.InvariantCultureIgnoreCase))
                _zone.TTL = UInt32.Parse (_reader.Expect (TokenType.Number).Value);
            else
                throw new ZoneFileException ($"Unknown directive '{directive}'");
        }

        void ParseRecord (string name)
        {
            RecordClass @class = RecordClass.ANY;
            UInt32 ttl = _zone.TTL;
            RecordType type;

            try { @class = (RecordClass) Enum.Parse (typeof (RecordClass), _reader.Expect (TokenType.NonBlank).Value); }
            catch { }

            if (_reader.Peek ().Type == TokenType.Number)
                ttl = UInt32.Parse (_reader.Read ().Value);

            type = (RecordType) Enum.Parse (typeof (RecordType), _reader.Expect (TokenType.NonBlank).Value);

            RecordBase record = RecordBase.Create (this._zone, name, @class, type, ttl);

            if (_reader.Peek ().Type == TokenType.LuaScript)
                record.SetScript (_reader.Read ().Value);
            else
            {
                if (record is HostnameRecord)
                {
                    ((HostnameRecord) record).Hostname = _reader.Expect (TokenType.NonBlank).Value;
                }
                else if (record is AddressRecord)
                {
                    ((AddressRecord) record).Address = _reader.Expect (TokenType.NonBlank).Value;
                }
                else if (record is SOARecord)
                {
                    var soar = (SOARecord) record;

                    soar.Data.Hostname = _reader.Expect (TokenType.NonBlank).Value;
                    soar.Data.AdminAddress = _reader.Expect (TokenType.NonBlank).Value;

                    var tgroup = _reader.Expect (TokenType.Group);
                    var tks = _groupTokenizer.Tokenize (tgroup.Value, lineOffset: tgroup.Line)
                                             .Where (t => t.Type == TokenType.Number);

                    var greader = new TokenReader (tks);
                    soar.Data.SerialNumber = UInt32.Parse (greader.Expect (TokenType.Number).Value);
                    soar.Data.SlaveRefreshPeriod = UInt32.Parse (greader.Expect (TokenType.Number).Value);
                    soar.Data.SlaveRetryTime = UInt32.Parse (greader.Expect (TokenType.Number).Value);
                    soar.Data.SlaveExpirationTime = UInt32.Parse (greader.Expect (TokenType.Number).Value);
                    soar.Data.MinimumTTL = UInt32.Parse (greader.Expect (TokenType.Number).Value);
                }
                else if (record is MXRecord)
                {
                    var mx = (MXRecord) record;
                    mx.Data.Preference = int.Parse (_reader.Expect (TokenType.Number).Value);
                    mx.Data.Hostname = _reader.Expect (TokenType.NonBlank).Value;
                }
                else if (record is NULLRecord)
                {
                    var nr = (NULLRecord) record;
                    nr.Data = NULLRecord.ParseData (_reader.Expect (TokenType.HexData).Value);
                }
                else if (record is TXTRecord)
                {
                    var tr = (TXTRecord) record;
                    tr.Data = _reader.Expect (TokenType.StringData).Value;
                }
                else
                {
                    Log.Info ($"Ignoring unknown record of type {record.Type}", "Parser");
                    record = null;
                }
            }

            if (record != null)
                _zone.AddRecord (record);
        }

        Zone _zone;
        readonly string _input;

        enum TokenType
        {
            None,
            Comment,
            Directive,
            NonBlank,
            Blank,
            EOL,
            LuaScript,
            Number,
            EOF,
            Group,
            StringData,
            HexData
        }

        class Token
        {
            public TokenType Type { get; private set; }
            public string Value { get; private set; }
            public int Line { get; private set; }

            public Token (TokenType type, string value, int line)
            {
                this.Type = type;
                this.Value = value;
                this.Line = line;
            }
        }

        readonly TokenReader _reader;

        class TokenReader
        {
            public TokenReader (IEnumerable<Token> tokens)
            {
                this._tokens = tokens.ToArray ();

                _offset = 0;
                Read ();
            }

            public bool Consume (TokenType type)
            {
                if (current.Type != type)
                    return false;

                Read ();
                return true;
            }

            public Token ExpectAny (params TokenType[] types)
            {
                if (Array.IndexOf (types, current.Type) == -1)
                    throw new ZoneFileException (current.Line, $"Unexpected '{current.Type}'.");

                return Read ();
            }

            public Token Expect (TokenType type)
            {
                if (current.Type != type)
                    throw new ZoneFileException (current.Line, $"Expected '{type}'. Found '{current.Type}'");

                return Read ();
            }

            public Token Read ()
            {
                if (current != null && current.Type == TokenType.EOF)
                    return current;

                var result = current;
                current = (_offset >= _tokens.Length) ? new Token (TokenType.EOF, string.Empty, -1) : _tokens[_offset++];
                return result;
            }

            public Token Peek () => current;

            int _offset;
            Token current;

            readonly Token[] _tokens;
        }

        class TokenMatch
        {
            public static readonly TokenMatch None = new TokenMatch (TokenType.None, string.Empty);

            public TokenType TokenType { get; private set; }
            public string RawValue { get; private set; }
            public string Value { get; private set; }

            TokenMatch () { }

            public TokenMatch (TokenType tokenType, string rawValue, string value=null)
            {
                this.TokenType = tokenType;
                this.RawValue = rawValue;
                this.Value = value ?? rawValue;
            }
        }

        class Tokenizer
        {
            public Tokenizer (IEnumerable<IMatcher> tokens)
            {
                this._tokens = tokens;
            }

            public IEnumerable<Token> Tokenize (string input, int lineOffset=1, bool skipBlanks = true, bool skipComments = true)
            {
                int offset = 0;
                int line = lineOffset;

                do
                {
                    TokenMatch lastMatch = TokenMatch.None;

                    foreach (var tok in _tokens)
                    {
                        var m = tok.Match (input, offset);
                        if (m == TokenMatch.None)
                            continue;

                        if (lastMatch == TokenMatch.None || m.Value.Length > lastMatch.RawValue.Length)
                        {
                            lastMatch = m;
                            line += m.RawValue.Count (c => c == '\n');
                        }
                    }

                    if (lastMatch.TokenType == TokenType.None)
                        throw new ZoneFileException (line, $"Unexpected input '{input.Substring (offset, 5)}...'.");

                    bool ignore = (skipBlanks && lastMatch.TokenType == TokenType.Blank)
                               || (skipComments && lastMatch.TokenType == TokenType.Comment);

                    if (!ignore)
                        yield return new Token (lastMatch.TokenType, lastMatch.Value, line);

                    offset += lastMatch.RawValue.Length;
                } while (offset < input.Length);
            }

            readonly IEnumerable<IMatcher> _tokens;
        }

        interface IMatcher
        {
            TokenType TokenType { get; }
            int Priority { get; }
            TokenMatch Match (string input, int offset);
        }

        class RegexMatcher
            : IMatcher
        {
            public TokenType TokenType { get; private set; }
            public int Priority { get; private set; }

            public RegexMatcher (string pattern, TokenType tokenType, int valueGroup=0, int priority=1)
            {
                this.TokenType = tokenType;
                this.Priority = priority;

                _valueGroup = valueGroup;
                _regex = new Regex (@"\G" + pattern);
            }

            public TokenMatch Match (string input, int offset)
            {
                var m = _regex.Match (input, offset);
                if (!m.Success)
                    return TokenMatch.None;

                string value = m.Groups[_valueGroup].Value;
                return new TokenMatch (this.TokenType, m.Value, value);
            }

            readonly Regex _regex;
            readonly int _valueGroup;
        }

        class StringMatcher
            : IMatcher
        {
            public TokenType TokenType { get; }
            public int Priority { get; }

            public StringMatcher (string stringStart, string stringEnd, TokenType tokenType, int priority=1)
            {
                this.TokenType = tokenType;
                this.Priority = priority;

                _start = stringStart;
                _end = stringEnd;
            }

            public TokenMatch Match (string input, int offset)
            {
                if (offset >= input.Length - _start.Length)
                    return TokenMatch.None;

                if (!input.Substring (offset, _start.Length).Equals (_start))
                    return TokenMatch.None;

                int endIndex = input.IndexOf (_end, offset + _start.Length);
                if (endIndex == -1)
                    return TokenMatch.None;

                string rawValue = input.Substring (offset, endIndex + _end.Length - offset);
                string value = rawValue.Substring (_start.Length, rawValue.Length - _start.Length - _end.Length);

                return new TokenMatch (this.TokenType, rawValue, value);
            }

            readonly string _start;
            readonly string _end;
        }

        static readonly Tokenizer _fileTokenizer = new Tokenizer (new List<IMatcher> {
            new RegexMatcher (@";[^\n]*", TokenType.Comment),
            new RegexMatcher (@"\$[A-Za-z_][A-Za-z0-9_]*", TokenType.Directive),
            new StringMatcher (@"(", ")", TokenType.Group),
            new StringMatcher (@"<?lua", "?>", TokenType.LuaScript),
            new StringMatcher ("\"", "\"", TokenType.StringData),
            new RegexMatcher (@"0x([0-9A-Fa-f]+)", TokenType.HexData, valueGroup:1),
            new RegexMatcher (@"\d+", TokenType.Number),
            new RegexMatcher (@"[^\s]+", TokenType.NonBlank, priority:0),
            new RegexMatcher (@"\n", TokenType.EOL),
            new RegexMatcher (@"[\s\t\r]", TokenType.Blank),
        });

        static readonly Tokenizer _groupTokenizer = new Tokenizer (new List<IMatcher> {
            new RegexMatcher (@";[^\n]*", TokenType.Comment),
            new RegexMatcher (@"\n", TokenType.EOL),
            new RegexMatcher (@"[\s\t\r]", TokenType.Blank),
            new RegexMatcher (@"\d+", TokenType.Number),
        });
    }
}
