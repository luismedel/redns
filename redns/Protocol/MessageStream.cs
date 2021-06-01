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
using System.IO;
using System.Text;
using redns.Protocol.Exceptions;

namespace redns.Protocol
{
    class MessageStream
        : Stream
    {
        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => _inner.CanSeek;
        public override bool CanWrite => _inner.CanWrite;
        public override long Length => _inner.Length;

        public override long Position
        {
            get => _inner.Position;
            set => _inner.Position = value;
        }

        public MessageStream (int capacity)
            : this (new MemoryStream (capacity))
        {
        }

        public MessageStream (byte[] buffer)
            : this (new MemoryStream (buffer))
        {
        }

        public MessageStream (Stream stream)
            : base ()
        {
            _inner = stream;
        }

        public string ReadFQName ()
        {
            // TODO: Add compression support

            byte[] name = new byte[256];
            int offset = 0;

            do
            {
                int length = ReadByte ();
                if (length == 0)
                {
                    if (offset == 0)
                        name[offset++] = (byte) '.';
                    break;
                }
                else
                {
                    if (offset != 0)
                        name[offset++] = (byte) '.';

                    _inner.Read (name, offset, length);
                    offset += length;
                }
            } while (true);

            return Encoding.ASCII.GetString (name, 0, offset);
        }

        public void WriteFQName (string name)
        {
            // TODO: Add compression support

            var parts = name.Split ('.');
            foreach (var s in parts)
                WritePrefixedString (s, 63);

            if (parts[parts.Length - 1].Length != 0)
                _inner.WriteByte (0);
        }

        public string ReadPrefixedString ()
        {
            return ReadString (_inner.ReadByte ());
        }

        public string ReadString (int length)
        {
            byte[] bytes = new byte[length];
            _inner.Read (bytes, 0, length);
            return Encoding.ASCII.GetString (bytes);
        }

        public void WritePrefixedString (string s, int maxLength=255)
        {
            byte length = (byte) Math.Min (maxLength, s.Length);
            if (s.Length > length)
                throw new StringTooLongException (s, maxLength);

            _inner.WriteByte (length);
            _inner.Write (Encoding.ASCII.GetBytes (s), 0, length);
        }

        public UInt16 ReadWord ()
        {
            return (UInt16) ((_inner.ReadByte () << 8) | _inner.ReadByte ());
        }

        public void WriteWord (int value)
        {
            _inner.WriteByte ((byte) ((value & 0xff00) >> 8));
            _inner.WriteByte ((byte) (value & 0x00ff));
        }

        public UInt32 ReadDWord ()
        {
            return (UInt32) (_inner.ReadByte () << 24)
                 | (UInt32) (_inner.ReadByte () << 16)
                 | (UInt32) (_inner.ReadByte () << 8)
                 | (UInt32) _inner.ReadByte ();
        }

        public void WriteDWord (UInt32 value)
        {
            _inner.WriteByte ((byte) ((value & 0xff000000) >> 24));
            _inner.WriteByte ((byte) ((value & 0x00ff0000) >> 16));
            _inner.WriteByte ((byte) ((value & 0x0000ff00) >> 8));
            _inner.WriteByte ((byte) (value & 0x000000ff));
        }

        public void WriteAddress (byte[] value)
        {
            _inner.Write (value, 0, value.Length);
        }

        public override void Flush ()
        {
            _inner.Flush ();
        }

        public override int Read (byte[] buffer, int offset, int count)
        {
            return _inner.Read (buffer, offset, count);
        }

        public override long Seek (long offset, SeekOrigin origin)
        {
            return _inner.Seek (offset, origin);
        }

        public override void SetLength (long value)
        {
            _inner.SetLength (value);
        }

        public override void Write (byte[] buffer, int offset, int count)
        {
            _inner.Write (buffer, offset, count);
        }

        public byte[] GetBuffer ()
        {
            var bytes = (_inner as MemoryStream)?.GetBuffer ();
            if (bytes == null)
                return new byte[0];

            if (bytes.Length == _inner.Position)
                return bytes;

            byte[] slice = new byte[_inner.Position];
            Buffer.BlockCopy (bytes, 0, slice, 0, slice.Length);

            return slice;
        }

        readonly Stream _inner;
    }
}
