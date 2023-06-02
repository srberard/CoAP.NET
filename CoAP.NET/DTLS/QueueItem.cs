/*
 * Copyright (c) 2023-, Stephen Berard <stephen.berard@outlook.com>
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY.
 *
 * This file is part of the CoAP.NET, a CoAP framework in C#.
 * Please see README for more information.
 */

namespace CoAP.DTLS
{
    /// <summary>
    /// QueueItems are used for items in the
    /// </summary>
    public class QueueItem
    {
        private readonly byte[] _data;

        public QueueItem(byte[] data) {
            _data = data;
        }

        public byte[] Data {
            get => _data;
        }

        public int Length {
            get => Data.Length;
        }
    }
}