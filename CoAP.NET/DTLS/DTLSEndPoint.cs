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
using CoAP.Codec;
using CoAP.Net;

namespace CoAP.DTLS
{
    /// <summary>
    /// This class is used to support the use of DTLS for servers.
    /// This class supports both client and server sides of a DTLS connection.
    /// </summary>
    public class DTLSEndPoint : CoAPEndPoint
    {
        /// <inheritdoc/>
        public DTLSEndPoint(TlsKeyPairSet serverKeys, TlsPskKeySet userKeys) : this(serverKeys, userKeys, 0, CoapConfig.Default) {
        }

        /// <inheritdoc/>
        public DTLSEndPoint(TlsKeyPairSet serverKeys, TlsPskKeySet userKeys, ICoapConfig config) : this(serverKeys, userKeys, 0, config) {
        }

        /// <inheritdoc/>
        public DTLSEndPoint(TlsKeyPairSet keysServer, TlsPskKeySet keysUser, Int32 port) : this(new DTLSChannel(keysServer, keysUser, port), CoapConfig.Default) {
        }

        /// <inheritdoc/>
        public DTLSEndPoint(TlsKeyPairSet keyServer, TlsPskKeySet keysUser, int port, ICoapConfig config) : this(new DTLSChannel(keyServer, keysUser, port), config) { }

        /// <inheritdoc/>
        public DTLSEndPoint(TlsKeyPairSet keysServer, TlsPskKeySet keysUser, System.Net.EndPoint localEndPoint) : this(keysServer, keysUser, localEndPoint, CoapConfig.Default) {
        }

        /// <inheritdoc/>
        public DTLSEndPoint(TlsKeyPairSet keysServer, TlsPskKeySet keysUser, System.Net.EndPoint localEndPoint, ICoapConfig config) : this(new DTLSChannel(keysServer, keysUser, localEndPoint), config) {
        }

        /// <summary>
        /// Instantiates a new DTLS endpoint with the specific channel and configuration
        /// </summary>
        /// <param name="channel">The DTLS Channel object to use for low level transmission</param>
        /// <param name="config">Configuration interface</param>
        public DTLSEndPoint(DTLSChannel channel, ICoapConfig config) : base(channel, config) {
            // Stack.Remove(Stack.Get("Reliability"));
            MessageEncoder = UdpCoapMesageEncoder;
            MessageDecoder = UdpCoapMessageDecoder;
            EndpointSchema = new[] { "coaps", "coaps+udp" };
            channel.TlsEventHandler += OnTlsEvent;
        }

        private static IMessageDecoder UdpCoapMessageDecoder(byte[] data) {
            return new Spec.MessageDecoder18(data);
        }

        private static IMessageEncoder UdpCoapMesageEncoder() {
            return new Spec.MessageEncoder18();
        }

        public EventHandler<TlsEvent> TlsEventHandler;

        private void OnTlsEvent(Object o, TlsEvent e) {
            EventHandler<TlsEvent> handler = TlsEventHandler;
            if (handler != null) {
                handler(o, e);
            }
        }
    }
}