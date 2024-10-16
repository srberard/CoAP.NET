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
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using CoAP.Channel;
using CoAP.Log;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Tls;

namespace CoAP.DTLS
{
    /// <summary>
    /// Channel implementation to support DTLS that
    /// </summary>
    public class DTLSChannel : IChannel
    {
        private static readonly ILogger _logger = LogManager.GetLogger<DTLSChannel>();
        private System.Net.EndPoint _localEP;
        private Int32 _receiveBufferSize;
        private Int32 _sendBufferSize;
        private Int32 _receivePacketSize;
        private readonly int _port;
        private UDPChannel _udpChannel;
        private TlsKeyPairSet _serverKeys;
        private TlsPskKeySet _userKeys;

        public DTLSChannel(TlsKeyPairSet serverKeys, TlsPskKeySet userKeys) : this(serverKeys, userKeys, 0) {
        }

        public DTLSChannel(TlsKeyPairSet serverKeys, TlsPskKeySet userKeys, Int32 port) {
            _port = port;
            _userKeys = userKeys;
            _serverKeys = serverKeys;
        }

        /// <summary>
        /// Create a DTLS channel with remote ad local keys.
        /// </summary>
        /// <param name="serverKeys"></param>
        /// <param name="userKeys"></param>
        /// <param name="ep"></param>
        public DTLSChannel(TlsKeyPairSet serverKeys, TlsPskKeySet userKeys, System.Net.EndPoint ep) {
            _localEP = ep;
            _userKeys = userKeys;
            _serverKeys = serverKeys;
        }

        /// <inheritdoc/>
        public event EventHandler<DataReceivedEventArgs> DataReceived;

        /// <inheritdoc/>
        public System.Net.EndPoint LocalEndPoint {
            get { return _udpChannel == null ? (_localEP ?? new IPEndPoint(IPAddress.IPv6Any, _port)) : _udpChannel.LocalEndPoint; }
        }

        /// <summary>
        /// Gets or sets the <see cref="Socket.ReceiveBufferSize"/>.
        /// </summary>
        public Int32 ReceiveBufferSize {
            get { return _receiveBufferSize; }
            set { _receiveBufferSize = value; }
        }

        /// <summary>
        /// Gets or sets the <see cref="Socket.SendBufferSize"/>.
        /// </summary>
        public Int32 SendBufferSize {
            get { return _sendBufferSize; }
            set { _sendBufferSize = value; }
        }

        /// <summary>
        /// Gets or sets the size of buffer for receiving packet.
        /// The default value is <see cref="DefaultReceivePacketSize"/>.
        /// </summary>
        public Int32 ReceivePacketSize {
            get { return _receivePacketSize; }
            set { _receivePacketSize = value; }
        }

        private Int32 _running;

        public EventHandler<TlsEvent> TlsEventHandler;

        /// <inheritdoc/>
        public bool AddMulticastAddress(IPEndPoint ep) {
            return false;
        }

        public void Start() {
            if (System.Threading.Interlocked.CompareExchange(ref _running, 1, 0) > 0) {
                return;
            }

            if (_udpChannel == null) {
                if (_localEP != null) {
                    _udpChannel = new UDPChannel(_localEP);
                } else {
                    _udpChannel = new UDPChannel(_port);
                }
            }

            _udpChannel.DataReceived += ReceiveData;

            _udpChannel.Start();
        }

        public void Stop() {
            lock (_sessionList) {
                foreach (DTLSSession session in _sessionList) {
                    session.Stop();
                }
                _sessionList.Clear();
            }
            _udpChannel.Stop();
        }

        /// <summary>
        /// We don't do anything for this right now because we don't have sessions.
        /// </summary>
        /// <param name="session"></param>
        public void Abort(ISession session) {
            return;
        }

        /// <summary>
        /// We don't do anything for this right now because we don't have sessions.
        /// </summary>
        /// <param name="session"></param>
        public void Release(ISession session) {
            return;
        }

        public void Dispose() {
            _udpChannel.Dispose();
        }

        /// <summary>
        /// Get an existing session.  If one does not exist then create it and try
        /// to make a connection.
        /// </summary>
        /// <returns>session to use</returns>
        public ISession GetSession(System.Net.EndPoint ep) {
            DTLSSession session = null;
            try {
                IPEndPoint ipEndPoint = (IPEndPoint)ep;

                //  Do we already have a session setup for this?

                session = FindSession(ipEndPoint);
                if (session != null)
                    return session;

                //  No session - create a new one.
                _logger.LogTrace($"DtlsChannel.GetSession: Creating new session for {ep}");
                session = new DTLSSession(ipEndPoint, DataReceived, _serverKeys, _userKeys);
                AddSession(session);
                session.TlsEventHandler += MyTlsEventHandler;

                session.Connect(_udpChannel);
            }
            catch (Exception e) {
                _logger.LogError($"Exception thrown in DTLSClientChannel GetSession {e.Message}");
                ;
            }

            return session;
        }

        private void MyTlsEventHandler(Object o, TlsEvent e) {
            EventHandler<TlsEvent> handler = TlsEventHandler;
            if (handler != null) {
                handler(o, e);
            }
        }

        public void Send(byte[] data, ISession sessionReceive, System.Net.EndPoint ep) {
            try {
                IPEndPoint ipEP = (IPEndPoint)ep;

                DTLSSession session = FindSession(ipEP);
                if (session == null) {
                    session = new DTLSSession(ipEP, DataReceived, _serverKeys, _userKeys);
                    session.TlsEventHandler += MyTlsEventHandler;
                    AddSession(session);
                    session.Connect(_udpChannel);
                } else if (session != sessionReceive) {
                    //  Don't send it
                    return;
                }
                session.Queue.Enqueue(new QueueItem(/*null, */ data));
                session.WriteData();
            }
            catch (Exception e) {
                _logger.LogError($"Exception thrown in DTLSClientChannel Sending: {e.Message}", e);
            }
        }

        private void ReceiveData(Object sender, DataReceivedEventArgs e) {
            _logger.LogTrace($"DtlsChannel.ReceiveData called.");

            lock (_sessionList) {
                foreach (DTLSSession session in _sessionList) {
                    if (e.EndPoint.Equals(session.EndPoint)) {
                        short recordType = TlsUtilities.ReadUint8(e.Data, 0);
                        int epoch = TlsUtilities.ReadUint16(e.Data, 3);
                        short handshakeType = TlsUtilities.ReadUint8(e.Data, 13);
                        if ((recordType == ContentType.handshake) && (epoch == 0) && (handshakeType == HandshakeType.client_hello)) {
                            // TODO:  Properly implement validation of a new session with existing parameters
                            // This is a big hack to remove the old session, per RFC6347 section 4.2.8 (DTLS 1.2) and RFC9147 section 5.11 (DTLS 1.3)
                            // a new connection can be established with the same parameters, however, it is required that the handshake properly
                            // complete before the old session is removed by the server.
                            //
                            // This code does not do that, instead it simply discards the old session in favor of the new.
                            _sessionList.Remove(session);
                            _logger.LogTrace($"DtlsChannel.ReceiveData: Removing old session for {e.EndPoint}");
                        } else {
                            _logger.LogTrace($"DtlsChannel.ReceiveData: Using existing session {session.EndPoint}");
                            session.ReceiveData(sender, e);
                        }

                        return;
                    }
                }

                DTLSSession sessionNew = new DTLSSession((IPEndPoint)e.EndPoint, DataReceived, _serverKeys, _userKeys);
                sessionNew.TlsEventHandler = MyTlsEventHandler;
                _sessionList.Add(sessionNew);
                Task.Run(() => Accept(sessionNew, e.Data));
            }
        }

        private void Accept(DTLSSession session, byte[] message) {
            _logger.LogTrace($"DtlsChannel.Accept called");
            try {
                session.Accept(_udpChannel, message);
            }
            catch (Exception) {
                lock (_sessionList) {
                    _sessionList.Remove(session);
                }
            }
        }

        private static List<DTLSSession> _sessionList = new List<DTLSSession>();

        private static void AddSession(DTLSSession session) {
            lock (_sessionList) {
                _sessionList.Add(session);
            }
        }

        private static DTLSSession FindSession(IPEndPoint ipEP) {
            lock (_sessionList) {
                foreach (DTLSSession session in _sessionList) {
                    if (session.EndPoint.Equals(ipEP))
                        return session;
                }
            }

            return null;
        }
    }
}