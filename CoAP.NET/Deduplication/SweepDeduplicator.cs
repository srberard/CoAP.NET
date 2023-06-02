/*
 * Copyright (c) 2011-2014, Longxiang He <helongxiang@smeshlink.com>,
 * SmeshLink Technology Co.
 *
 * Copyright (c) 2023-, Stephen Berard <stephen.berard@outlook.com>
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY.
 *
 * This file is part of the CoAP.NET, a CoAP framework in C#.
 * Please see README for more information.
 */

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Timers;
using CoAP.Net;

namespace CoAP.Deduplication
{
    internal class SweepDeduplicator : IDeduplicator
    {
        private readonly ConcurrentDictionary<Exchange.KeyID, Exchange> _incommingMessages
            = new ConcurrentDictionary<Exchange.KeyID, Exchange>();

        private Timer _timer;
        private readonly ICoapConfig _config;
        // private int _period;

        public SweepDeduplicator(ICoapConfig config) {
            _config = config;
            _timer = new Timer(config.MarkAndSweepInterval);
            _timer.Elapsed += Sweep;
        }

        private void Sweep(Object obj, ElapsedEventArgs e) {
            SweepDeduplicator sender = this;

            DateTime oldestAllowed = DateTime.Now.AddMilliseconds(-sender._config.ExchangeLifetime);
            List<Exchange.KeyID> keysToRemove = new List<Exchange.KeyID>();
            foreach (KeyValuePair<Exchange.KeyID, Exchange> pair in sender._incommingMessages) {
                if (pair.Value.Timestamp < oldestAllowed) {
                    keysToRemove.Add(pair.Key);
                }
            }
            if (keysToRemove.Count > 0) {
                Exchange ex;
                foreach (Exchange.KeyID key in keysToRemove) {
                    sender._incommingMessages.TryRemove(key, out ex);
                }
            }
        }

        /// <inheritdoc/>
        public void Start() {
            _timer.Start();
        }

        /// <inheritdoc/>
        public void Stop() {
            _timer.Stop();
            Clear();
        }

        /// <inheritdoc/>
        public void Clear() {
            _incommingMessages.Clear();
        }

        /// <inheritdoc/>
        public Exchange FindPrevious(Exchange.KeyID key, Exchange exchange) {
            Exchange prev = null;
            _incommingMessages.AddOrUpdate(key, exchange, (k, v) => {
                prev = v;
                return exchange;
            });
            return prev;
        }

        /// <inheritdoc/>
        public Exchange Find(Exchange.KeyID key) {
            Exchange prev;
            _incommingMessages.TryGetValue(key, out prev);
            return prev;
        }

        /// <inheritdoc/>
        public void Dispose() {
            _timer.Dispose();
            _timer = null;
        }
    }
}