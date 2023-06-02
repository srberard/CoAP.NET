/*
 * Copyright (c) 2023-, Stephen Berard <stephen.berard@outlook.com>
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY.
 *
 * This file is part of the CoAP.NET, a CoAP framework in C#.
 * Please see README for more information.
 */

using System;

namespace CoAP
{
    public interface ISession
    {
        /// <summary>
        /// Occurs when some bytes are received in this channel.
        /// </summary>
        event EventHandler<SessionEventArgs> SessionEvent;

        /// <summary>
        /// Is the session reliable?
        /// </summary>
        bool IsReliable { get; }

        /// <summary>
        /// True means that it is supported, False means that it may be supported.
        /// </summary>
        bool BlockTransfer { get; set; }

        /// <summary>
        /// Size of maximum message the other size is able to process
        /// </summary>
        int MaxSendSize { get; set; }
    }
}