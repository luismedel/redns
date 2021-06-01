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
using System.Net;
using System.Text;
using redns.Protocol.ResourceRecords;

namespace redns.Protocol
{
    class Message
    {
        public IPEndPoint RemoteEndPoint { get; private set; }

        public UInt16 Id { get; set; }
        public UInt16 Detail { get; set; }

        public List<Query> Queries { get; private set; } = new List<Query> ();
        public List<Answer> Answers { get; private set; } = new List<Answer> ();
        public List<Answer> AuthoritativeAnswers { get; private set; } = new List<Answer> ();
        public List<Answer> AdditionalAnswers { get; private set; } = new List<Answer> ();

        public bool IsQuery
        {
            get => (Detail & 0x8000) == 0;
            set => Detail = (UInt16) (value ? (Detail & ~(1 << 15)) : (Detail | (1 << 15)));
        }

        public MessageOpcode Opcode
        {
            get => (MessageOpcode) ((Detail >> 11) & 0x0f);
            set => Detail = (UInt16) ((Detail & 0x87ff) | (UInt16) value << 11);
        }

        public bool IsAuthoritative
        {
            get => ((Detail >> 10) & 1) == 1;
            set => Detail = (UInt16) (value ? (Detail | (1 << 10)) : (Detail & ~(1 << 10)));
        }

        public bool IsTruncated
        {
            get => ((Detail >> 9) & 1) == 1;
            set => Detail = (UInt16) (value ? (Detail | (1 << 9)) : (Detail & ~(1 << 9)));
        }

        public bool RecursionDesired
        {
            get => ((Detail >> 8) & 1) == 1;
            set => Detail = (UInt16) (value ? (Detail | (1 << 8)) : (Detail & ~(1 << 8)));
        }

        public bool IsRecursionAvailable
        {
            get => ((Detail >> 7) & 1) == 1;
            set => Detail = (UInt16) (value ? (Detail | (1 << 7)) : (Detail & ~(1 << 7)));
        }

        public int Reserved
        {
            get => (Detail >> 4) & 0x07;
            set => Detail = (UInt16) ((Detail & 0xff8f) | ((value & 0x07) << 4));
        }

        public ReturnCode RCode
        {
            get => (ReturnCode) (Detail & 0x0f);
            set => Detail = (UInt16) ((Detail & 0xfff0) | ((UInt16) value & 0x07));
        }

        public Message (IPEndPoint remoteEndPoint)
        {
            this.RemoteEndPoint = remoteEndPoint;
        }

        public Message GetResponse ()
        {
            return new Message (this.RemoteEndPoint) {
                Id = this.Id,
                Detail = this.Detail,
                IsQuery = false,
                RCode = ReturnCode.NoError,
            };
        }

        public void Serialize (MessageStream s)
        {
            s.WriteWord (Id);
            s.WriteWord (Detail);
            s.WriteWord (QDCount);
            s.WriteWord (ANCount);
            s.WriteWord (NSCount);
            s.WriteWord (ARCount);

            foreach (var q in Queries)
                q.Serialize (s);

            foreach (var a in Answers)
                a.Serialize (s);

            foreach (var a in AuthoritativeAnswers)
                a.Serialize (s);

            foreach (var a in AdditionalAnswers)
                a.Serialize (s);
        }

        public void Deserialize (MessageStream s)
        {
            Id = s.ReadWord ();
            Detail = s.ReadWord ();
            var qcount = s.ReadWord ();
            var ancount = s.ReadWord ();
            var nscount = s.ReadWord ();
            var arcount = s.ReadWord ();

            if (qcount > 1)
            {
                // As described in RFC-1035, one message can have multiple
                // queries. In practice, though, every implementation out there
                // expect only one query at most.
                Log.Warn ("Nonstandard message ({0} queries).", qcount);
            }

            Queries.Clear ();
            Answers.Clear ();
            AuthoritativeAnswers.Clear ();
            AdditionalAnswers.Clear ();

            for (int i = 0; i < qcount; i++)
            {
                var q = new Query (this);

                q.Deserialize (s);
                Queries.Add (q);
            }

            DeserializeAnswers (s, ancount, Answers);
            DeserializeAnswers (s, nscount, AuthoritativeAnswers);
            DeserializeAnswers (s, arcount, AdditionalAnswers);
        }

        void DeserializeAnswers (MessageStream s, int count, List<Answer> output)
        {
            for (int i = 0; i < count; i++)
            {
                string name = s.ReadFQName ();
                RecordType type = (RecordType) s.ReadWord ();
                RecordClass @class = (RecordClass) s.ReadWord ();

                var a = new Answer (name, type, @class, new GenericResourceRecord ());
                a.Deserialize (s);
                output.Add (a);
            }
        }

        public void Clear ()
        {
            Queries.Clear ();
            Answers.Clear ();
            AuthoritativeAnswers.Clear ();
            AdditionalAnswers.Clear ();
        }

        public byte[] GetBuffer (bool addSize)
        {
            int dataSize = GetSize ();
            int packetSize = dataSize + (addSize ? 2 : 0); // Additional word for size for TCP connections

            using (var s = new MessageStream (packetSize))
            {
                if (addSize)
                    s.WriteWord (dataSize);

                Serialize (s);
                return s.GetBuffer ();
            }
        }

        public int GetSize ()
        {
            return (6 * 2) + GetRSectionSize ();
        }

        public virtual int GetRSectionSize ()
        {
            int result = 0;

            if (Queries != null)
            {
                foreach (var q in Queries)
                    result += q.GetRSectionSize ();
            }

            if (Answers != null)
            {
                foreach (var ans in Answers)
                    result += ans.GetRSectionSize ();
            }

            if (AuthoritativeAnswers != null)
            {
                foreach (var ans in Answers)
                    result += ans.GetRSectionSize ();
            }

            if (AdditionalAnswers != null)
            {
                foreach (var ans in Answers)
                    result += ans.GetRSectionSize ();
            }

            return result;
        }

        public override string ToString ()
        {
            StringBuilder sb = new StringBuilder ();
            sb.AppendLine ($"Id: {Id}");
            sb.AppendLine ($"IsQuery: {IsQuery}");
            sb.AppendLine ($"Opcode: {Opcode}");
            sb.AppendLine ($"IsAuthoritative: {IsAuthoritative}");
            sb.AppendLine ($"IsTruncated: {IsTruncated}");
            sb.AppendLine ($"RecursinDesired: {RecursionDesired}");
            sb.AppendLine ($"RecursionAvailable: {IsRecursionAvailable}");
            sb.AppendLine ($"Reserved: {Reserved}");
            sb.AppendLine ($"Rcode: {RCode}");
            sb.AppendLine ($"QDCount: {QDCount}");
            sb.AppendLine ($"ANCount: {ANCount}");
            sb.AppendLine ($"NSCount: {NSCount}");
            sb.AppendLine ($"ARCount: {ARCount}");

            return sb.ToString ();
        }

        int QDCount => Queries.Count;
        int ANCount => Answers.Count;
        int NSCount => AuthoritativeAnswers.Count;
        int ARCount => AdditionalAnswers.Count;
    }
}
