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
    public class SessionEventArgs : EventArgs
    {
        /// <summary>
        /// List of all events that could occur
        /// </summary>
        public enum SessionEvent
        { Closed = 1 };

        /// <summary>
        /// What session did the event occur on
        /// </summary>
        public ISession Session { get; set; }

        /// <summary>
        /// What was the event that occured
        /// </summary>
        public SessionEvent Event { get; set; }

        /// <summary>
        /// Create the security event
        /// </summary>
        /// <param name="myEvent">What event</param>
        /// <param name="session">What Session</param>
        public SessionEventArgs(SessionEvent myEvent, ISession session) {
            Session = session;
            Event = myEvent;
        }
    }
}