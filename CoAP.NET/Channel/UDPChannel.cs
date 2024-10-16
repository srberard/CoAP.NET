/*
 * Copyright (c) 2011-2014, Longxiang He <helongxiang@smeshlink.com>,
 * SmeshLink Technology Co.
 *
 * Copyright (c) 2019-2020, Jim Schaad <ietf@augustcellars.com>
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
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using CoAP.Log;
using Microsoft.Extensions.Logging;

namespace CoAP.Channel
{
    /// <summary>
    /// Channel via UDP protocol.
    /// </summary>
    public partial class UDPChannel : IChannel, ISession
    {
        /// <summary>
        /// Default size of buffer for receiving packet.
        /// </summary>
        public const int DefaultReceivePacketSize = 4096;

        private static ILogger _logger = LogManager.GetLogger<UDPChannel>();
        private readonly SocketSet _unicast;
        private int _running;
        private int _writing;
        private readonly ConcurrentQueue<RawData> _sendingQueue = new ConcurrentQueue<RawData>();
        private bool UseReceiveMessageFrom = true;

        /// <inheritdoc/>
        public event EventHandler<DataReceivedEventArgs> DataReceived;

        /// <summary>
        /// Initializes a UDP channel with a random port.
        /// </summary>
        public UDPChannel()
            : this(0) {
        }

        /// <summary>
        /// Initializes a UDP channel with the given port, both on IPv4 and IPv6.
        /// </summary>
        public UDPChannel(int port) {
            _unicast = SocketSet.Find(port);
            if (_unicast != null) {
                throw new CoAPException("Cannot open the same port twice");
            }

            _unicast = new SocketSet(port);
        }

        /// <summary>
        /// Initializes a UDP channel with the specific endpoint.
        /// We only support IP endpoints - so throw if it isn't one
        /// </summary>
        public UDPChannel(System.Net.EndPoint localEP) {
            _unicast = SocketSet.Find((IPEndPoint)localEP);
            if (_unicast != null) {
                throw new CoAPException("Cannot open the same address twice");
            }
            _unicast = new SocketSet((IPEndPoint)localEP);
        }

        /// <inheritdoc/>
        public System.Net.EndPoint LocalEndPoint =>
            _unicast._socket == null ? _unicast.LocalEP : _unicast._socket.Socket.LocalEndPoint;

        /// <summary>
        /// Gets or sets the <see cref="Socket.ReceiveBufferSize"/>.
        /// </summary>
        public int ReceiveBufferSize { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="Socket.SendBufferSize"/>.
        /// </summary>
        public int SendBufferSize { get; set; }

        /// <summary>
        /// Gets or sets the size of buffer for receiving packet.
        /// The default value is <see cref="DefaultReceivePacketSize"/>.
        /// </summary>
        public int ReceivePacketSize { get; set; } = DefaultReceivePacketSize;

        /// <summary>
        /// True means that it is supported, False means that it may be supported.
        /// </summary>
        public bool BlockTransfer { get; set; } = false;

        /// <summary>
        /// Max message size
        /// </summary>
        public int MaxSendSize { get; set; }

        private readonly List<SocketSet> _listMultiCastEndpoints = new List<SocketSet>();

        /// <inheritdoc/>
        public bool AddMulticastAddress(IPEndPoint ep) //   IPAddress ep, int port)
        {
            IPEndPoint baseEndPoint = new IPEndPoint(ep.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, ep.Port);
            SocketSet s = SocketSet.Find(baseEndPoint);

            if (s == null) {
                s = new SocketSet(baseEndPoint) {
                    MulticastOnly = true
                };
                _listMultiCastEndpoints.Add(s);

                if (_running == 1) {
                    s.StartSocket(DefaultReceivePacketSize, SocketAsyncEventArgs_Completed);

                    if (ReceiveBufferSize > 0) {
                        s._socket.Socket.ReceiveBufferSize = ReceiveBufferSize;
                        if (s._socketBackup != null) {
                            s._socketBackup.Socket.ReceiveBufferSize = ReceiveBufferSize;
                        }
                    }

                    if (SendBufferSize > 0) {
                        s._socket.Socket.SendBufferSize = SendBufferSize;
                        if (s._socketBackup != null) {
                            s._socketBackup.Socket.SendBufferSize = SendBufferSize;
                        }
                    }

                    BeginReceive(s);
                }
            }

            s.AddMulticastAddress(ep);

            return true;
        }

        /// <inheritdoc/>
        public void Start() {
            if (System.Threading.Interlocked.CompareExchange(ref _running, 1, 0) > 0) {
                return;
            }

            _logger.LogTrace("UDPChannel.Start called.");

            try {
                _unicast.StartSocket(ReceivePacketSize, SocketAsyncEventArgs_Completed);

                if (ReceiveBufferSize > 0) {
                    _unicast._socket.Socket.ReceiveBufferSize = ReceiveBufferSize;
                    if (_unicast._socketBackup != null) {
                        _unicast._socketBackup.Socket.ReceiveBufferSize = ReceiveBufferSize;
                    }
                }

                if (SendBufferSize > 0) {
                    _unicast._socket.Socket.SendBufferSize = SendBufferSize;
                    if (_unicast._socketBackup != null) {
                        _unicast._socketBackup.Socket.SendBufferSize = SendBufferSize;
                    }
                }

                BeginReceive(_unicast);
            }
            catch (Exception) {
                _running = 0;
                throw;
            }
        }

        /// <inheritdoc/>
        public void Stop() {
            _logger.LogTrace("UPDChannel.Stop called");
            if (System.Threading.Interlocked.Exchange(ref _running, 0) == 0) {
                return;
            }

            _unicast.Dispose();
            foreach (SocketSet s in _listMultiCastEndpoints) {
                s.Dispose();
            }
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

        /// <inheritdoc/>
        public void Send(byte[] data, ISession sessionReceive, System.Net.EndPoint ep) {
            RawData raw = new RawData() {
                Data = data,
                EndPoint = ep
            };
            _sendingQueue.Enqueue(raw);
            if (System.Threading.Interlocked.CompareExchange(ref _writing, 1, 0) > 0) {
                return;
            }
            BeginSend();
        }

        /// <inheritdoc/>
        public void Dispose() {
            _logger.LogTrace("UDPChannel.Dispose called");

            Stop();
        }

        /// <inheritdoc/>
        public ISession GetSession(System.Net.EndPoint ep) {
            return this;
        }

        private void BeginReceive(SocketSet info) {
            _logger.LogTrace($"UDPChannel.BeginRecieve:  _running={_running}");

            if (_running > 0) {
                BeginReceive(info._socket);

                if (info._socketBackup != null) {
                    BeginReceive(info._socketBackup);
                }
            }
        }

        private void EndReceive(UDPSocket socket, byte[] buffer, int offset, int count, System.Net.EndPoint ep) {
            _logger.LogTrace($"UDPChannel.EndReceive: length={count}");

            if (count > 0) {
                byte[] bytes = new byte[count];
                Buffer.BlockCopy(buffer, offset, bytes, 0, count);

                if (ep.AddressFamily == AddressFamily.InterNetworkV6) {
                    IPEndPoint ipep = (IPEndPoint)ep;
                    if (IPAddressExtensions.IsIPv4MappedToIPv6(ipep.Address)) {
                        ep = new IPEndPoint(IPAddressExtensions.MapToIPv4(ipep.Address), ipep.Port);
                    }
                }

                System.Net.EndPoint epLocal = socket.Socket.LocalEndPoint;
                if (ep.AddressFamily == AddressFamily.InterNetworkV6) {
                    IPEndPoint ipLocal = (IPEndPoint)ep;
                    if (IPAddressExtensions.IsIPv4MappedToIPv6(ipLocal.Address)) {
                        epLocal = new IPEndPoint(IPAddressExtensions.MapToIPv4(ipLocal.Address), ipLocal.Port);
                    }
                }

                FireDataReceived(bytes, ep, epLocal);
            }

            _logger.LogTrace("UDPChannel.EndReceive: restart the read");

            BeginReceive(socket);
        }

        private void EndReceiveMessage(UDPSocket socket, byte[] buffer, int offset, int count, System.Net.EndPoint ep, IPAddress ipLocal) {
            _logger.LogTrace($"UDPChannel.EndReceive: length={count}");

            if (count > 0) {
                byte[] bytes = new byte[count];
                Buffer.BlockCopy(buffer, offset, bytes, 0, count);

                if (ep.AddressFamily == AddressFamily.InterNetworkV6) {
                    IPEndPoint ipep = (IPEndPoint)ep;
                    if (IPAddressExtensions.IsIPv4MappedToIPv6(ipep.Address)) {
                        ep = new IPEndPoint(IPAddressExtensions.MapToIPv4(ipep.Address), ipep.Port);
                    }
                }

                IPEndPoint epLocal;
                epLocal = (IPEndPoint)socket.Socket.LocalEndPoint;
                if (ipLocal != null) {
                    epLocal = new IPEndPoint(ipLocal, epLocal.Port);
                }

                if (epLocal.AddressFamily == AddressFamily.InterNetworkV6) {
                    if (IPAddressExtensions.IsIPv4MappedToIPv6(epLocal.Address)) {
                        epLocal = new IPEndPoint(IPAddressExtensions.MapToIPv4(epLocal.Address), epLocal.Port);
                    }
                }

                if (!socket.MulticastOnly || IPAddressExtensions.IsMulticastAddress(epLocal.Address)) {
                    FireDataReceived(bytes, ep, epLocal);
                }
            }

            _logger.LogTrace("UDPChannel.EndReceive: restart the read");
            BeginReceive(socket);
        }

        private void EndReceive(UDPSocket socket, Exception ex) {
            _logger.LogWarning("EndReceive: Fatal on receive ", ex);

            BeginReceive(socket);
        }

        private void FireDataReceived(byte[] data, System.Net.EndPoint ep, System.Net.EndPoint epLocal) {
            _logger.LogTrace($"UDPChannel.FireDataReceived: data length={data.Length}");

            EventHandler<DataReceivedEventArgs> h = DataReceived;
            if (h != null) {
                h(this, new DataReceivedEventArgs(data, ep, epLocal, this));
            }
        }

        private void BeginSend() {
            if (_running == 0) {
                return;
            }

            RawData raw;
            if (!_sendingQueue.TryDequeue(out raw)) {
                System.Threading.Interlocked.Exchange(ref _writing, 0);
                return;
            }

            UDPSocket socket = _unicast._socket;
            IPEndPoint remoteEP = (IPEndPoint)raw.EndPoint;

            if (remoteEP.AddressFamily == AddressFamily.InterNetwork) {
                if (_unicast._socketBackup != null) {
                    // use the separated socket of IPv4 to deal with IPv4 conversions.
                    socket = _unicast._socketBackup;
                } else if (_unicast._socket.Socket.AddressFamily == AddressFamily.InterNetworkV6) {
                    remoteEP = new IPEndPoint(IPAddressExtensions.MapToIPv6(remoteEP.Address), remoteEP.Port);
                }
            }

            BeginSend(socket, raw.Data, remoteEP);
        }

        private void EndSend(UDPSocket socket, int bytesTransferred) {
            BeginSend();
        }

        private void EndSend(UDPSocket socket, Exception ex) {
            // TODO may log exception?
            BeginSend();
        }

        private partial class UDPSocket : IDisposable
        {
            public readonly Socket Socket;
            public bool MulticastOnly { get; set; }
        }

        private class RawData
        {
            public byte[] Data;
            public System.Net.EndPoint EndPoint;
        }

        private class SocketSet
        {
            public IPEndPoint LocalEP { get; private set; }
            public int Port { get; private set; }
            public bool MulticastOnly { get; set; }
            public UDPSocket _socket;
            public UDPSocket _socketBackup;

            private readonly List<IPEndPoint> _multicastAddressList = new List<IPEndPoint>();

            private static readonly List<SocketSet> allSockets = new List<SocketSet>();

            public static SocketSet Find(IPEndPoint endPoint) {
                if (endPoint.Port != 0) {
                    foreach (SocketSet s in allSockets) {
                        if (((endPoint.Port == s.Port) && (s.LocalEP == null)) ||
                            (s.LocalEP != null &&
                             ((endPoint.AddressFamily == s.LocalEP.AddressFamily) &&
                              (endPoint.Address.Equals(s.LocalEP.Address))))) {
                            return s;
                        }
                    }
                }

                return null;
            }

            /// <summary>
            /// Locate a SocketSet based on the port number
            /// </summary>
            /// <param name="port"></param>
            /// <returns></returns>
            public static SocketSet Find(int port) {
                //  Port # of zero always creates a new one on a system assigned port number.
                if (port == 0) {
                    return null;
                }

                foreach (SocketSet s in allSockets) {
                    if (port == s.Port) {
                        //  This is the Any or AnyV6 and same port case.
                        return s;
                    } else if (s.LocalEP != null) {
                        if (port == s.LocalEP.Port &&
                            (s.LocalEP.AddressFamily == AddressFamily.InterNetwork || s.LocalEP.AddressFamily == AddressFamily.InterNetworkV6)) {
                            return s;
                        }
                    }
                }

                return null;
            }

            public SocketSet(IPEndPoint endPoint) {
                LocalEP = endPoint;
                allSockets.Add(this);
            }

            public SocketSet(int port) {
                Port = port;
                allSockets.Add(this);
            }

            public void Dispose() {
                _socket?.Dispose();
                _socketBackup?.Dispose();
                _socket = null;
                _socketBackup = null;
                allSockets.Remove(this);
            }

            public void AddMulticastAddress(IPEndPoint multicastAddr) {
                if ((multicastAddr.Port != Port) && (LocalEP != null && multicastAddr.Port != LocalEP.Port)) {
                    throw new ArgumentException("Must be the same port as the socket");
                }

                _multicastAddressList.Add(multicastAddr);
                if (_socket != null) {
                    DoJoin(multicastAddr);
                }
            }

            public void StartSocket(int receivePacketSize, EventHandler<SocketAsyncEventArgs> completed) {
                if (LocalEP == null) {
                    try {
                        _socket = SetupUDPSocket(AddressFamily.InterNetworkV6, receivePacketSize + 1, completed); // +1 to check for > ReceivePacketSize
                        _socket.MulticastOnly = MulticastOnly;
                    }
                    catch (SocketException e) {
                        if (e.SocketErrorCode == SocketError.AddressFamilyNotSupported) {
                            _socket = null;
                        } else {
                            throw;
                        }
                    }

                    if (_socket == null) {
                        // IPv6 is not supported, use IPv4 instead
                        _socket = SetupUDPSocket(AddressFamily.InterNetwork, receivePacketSize + 1, completed);
                        _socket.MulticastOnly = MulticastOnly;
                        _socket.Socket.Bind(new IPEndPoint(IPAddress.Any, Port));
                    } else {
                        // _socket.Socket.DualMode = true;

                        if (!_socket.Socket.DualMode) {
                            _logger.LogTrace("UDPChannel.StartSocket:  Create backup socket");

                            // IPv4-mapped address seems not to be supported, set up a separated socket of IPv4.
                            _socketBackup = SetupUDPSocket(AddressFamily.InterNetwork, receivePacketSize + 1, completed);
                            _socketBackup.MulticastOnly = MulticastOnly;
                        }

                        _socket.Socket.Bind(new IPEndPoint(IPAddress.IPv6Any, Port));
                        if (_socketBackup != null) {
                            if (Port == 0) {
                                Port = ((IPEndPoint)_socket.Socket.LocalEndPoint).Port;
                            }
                            _socketBackup.Socket.Bind(new IPEndPoint(IPAddress.Any, Port));
                        }
                    }

                    Port = ((IPEndPoint)_socket.Socket.LocalEndPoint).Port;
                } else {
                    _socket = SetupUDPSocket(LocalEP.AddressFamily, receivePacketSize + 1, completed);
                    _socket.MulticastOnly = MulticastOnly;

                    _socket.Socket.Bind(LocalEP);
                }

                foreach (IPEndPoint ep in _multicastAddressList) {
                    DoJoin(ep);
                }
            }

            private void DoJoin(IPEndPoint multicastAddr) {
                if (multicastAddr.Address.IsIPv6Multicast) {
                    try {
                        NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
                        foreach (NetworkInterface adapter in nics) {
                            if (!adapter.SupportsMulticast) continue;
                            if (adapter.OperationalStatus != OperationalStatus.Up) continue;
                            if (adapter.Supports(NetworkInterfaceComponent.IPv6)) {
                                IPInterfaceProperties properties = adapter.GetIPProperties();

                                foreach (UnicastIPAddressInformation ip in properties.UnicastAddresses) {
                                    if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) {
                                        IPv6InterfaceProperties v6Ip = adapter.GetIPProperties().GetIPv6Properties();
                                        IPv6MulticastOption mc = new IPv6MulticastOption(multicastAddr.Address, v6Ip.Index);
                                        try {
                                            _logger.LogTrace($"UDPChannel.DoJoin: {multicastAddr.Address} to {v6Ip.Index}");

                                            _socket.Socket.SetSocketOption(SocketOptionLevel.IPv6,
                                                SocketOptionName.AddMembership,
                                                mc);
                                        }
#pragma warning disable 168
                                        catch (SocketException e) {
#pragma warning restore 168
                                            _logger.LogInformation($"Start Multicast:  Address {LocalEP.Address} had an exception ${e.ToString()}");
                                        }

                                        break;
                                    }
                                }
                            }
                        }
                    }
#pragma warning disable 168
                    catch (SocketException e) {
#pragma warning restore 168
                        _logger.LogInformation($"Start Multicast:  Address {LocalEP.Address} had an exception ${e.ToString()}");
                        throw;
                    }
                } else {
                    try {
                        NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();

                        foreach (NetworkInterface adapter in nics) {
                            if (!adapter.SupportsMulticast) continue;
                            if (adapter.OperationalStatus != OperationalStatus.Up) continue;
                            if (adapter.Supports(NetworkInterfaceComponent.IPv4)) {
                                IPInterfaceProperties properties = adapter.GetIPProperties();

                                foreach (UnicastIPAddressInformation ip in properties.UnicastAddresses) {
                                    if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) {
                                        MulticastOption mc = new MulticastOption(multicastAddr.Address, ip.Address);
                                        if (_socketBackup != null) {
                                            _logger.LogTrace($"UDPChannel.DoJoin: (backup) {multicastAddr.Address} to {ip.Address}");

                                            _socketBackup.Socket.SetSocketOption(SocketOptionLevel.IP,
                                                SocketOptionName.AddMembership,
                                                mc);
                                        } else {
                                            _logger.LogTrace($"UDPChannel.DoJoin:  {multicastAddr.Address} to {ip.Address}");

                                            _socket.Socket.SetSocketOption(SocketOptionLevel.IP,
                                                SocketOptionName.AddMembership,
                                                mc);
                                        }
                                    }
                                }
                            }
                        }
                    }
#pragma warning disable 168
                    catch (SocketException e) {
#pragma warning restore 168

                        _logger.LogTrace($"Start Multicast:  Address {LocalEP.Address} had an exception ${e.ToString()}");
                        throw;
                    }
                }
            }

            private UDPSocket SetupUDPSocket(AddressFamily addressFamily, int bufferSize, EventHandler<SocketAsyncEventArgs> completed) {
                UDPSocket socket = new UDPSocket(addressFamily, bufferSize, completed);

                if (Environment.OSVersion.Platform == PlatformID.Win32NT ||
                    Environment.OSVersion.Platform == PlatformID.WinCE) {
                    // do not throw SocketError.ConnectionReset by ignoring ICMP Port Unreachable
                    const int SIO_UDP_CONNRESET = -1744830452;
                    try {
                        // Set the SIO_UDP_CONNRESET ioctl to true for this UDP socket. If this UDP socket
                        //    ever sends a UDP packet to a remote destination that exists but there is
                        //    no socket to receive the packet, an ICMP port unreachable message is returned
                        //    to the sender. By default, when this is received the next operation on the
                        //    UDP socket that send the packet will receive a SocketException. The native
                        //    (Winsock) error that is received is WSAECONNRESET (10054). Since we don't want
                        //    to wrap each UDP socket operation in a try/except, we'll disable this error
                        //    for the socket with this ioctl call.

                        socket.Socket.IOControl(SIO_UDP_CONNRESET, new byte[] { 0 }, null);
                    }
                    // ReSharper disable once EmptyGeneralCatchClause
                    catch (Exception) {
                    }
                }

                socket.Socket.SetSocketOption(addressFamily == AddressFamily.InterNetworkV6 ? SocketOptionLevel.IPv6 : SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
                return socket;
            }
        }

#pragma warning disable CS0067

        /// <inheritdoc/>
        public event EventHandler<SessionEventArgs> SessionEvent;

#pragma warning restore CS0067

        /// <inheritdoc/>
        public bool IsReliable => false;

        private UDPSocket NewUDPSocket(AddressFamily addressFamily, int bufferSize) {
            return new UDPSocket(addressFamily, bufferSize, SocketAsyncEventArgs_Completed);
        }

        private void BeginReceive(UDPSocket socket) {
            _logger.LogTrace($"UDPChannel.BeginReceive: socket={socket.Socket.LocalEndPoint}  _running={_running}");

            if (_running == 0) {
                return;
            }

            if (socket.ReadBuffer.RemoteEndPoint == null) {
                socket.ReadBuffer.RemoteEndPoint = socket.Socket.Connected ?
                    socket.Socket.RemoteEndPoint :
                    new IPEndPoint(socket.Socket.AddressFamily == AddressFamily.InterNetwork ?
                        IPAddress.Any : IPAddress.IPv6Any, 0);
                _logger.LogTrace($"UDPChannel.BeginReceive: Setup the remote endpoint {socket.ReadBuffer.RemoteEndPoint.ToString()}");
            }

            bool willRaiseEvent;
            try {
                _logger.LogTrace($"UDPChannel.BeginReceive:  Start async read");
                if (UseReceiveMessageFrom) {
                    willRaiseEvent = socket.Socket.ReceiveMessageFromAsync(socket.ReadBuffer);
                } else {
                    willRaiseEvent = socket.Socket.ReceiveFromAsync(socket.ReadBuffer);
                }
            }
            catch (NotImplementedException) {
                UseReceiveMessageFrom = false;
                willRaiseEvent = socket.Socket.ReceiveFromAsync(socket.ReadBuffer);
            }
            catch (ObjectDisposedException) {
                _logger.LogTrace($"UDPChannel.BeginRecieve:  Socket {socket.ToString()} is disposed");
                // do nothing
                return;
            }
            catch (Exception ex) {
                _logger.LogTrace($"UDPChannel.BeginReceive: Socket {socket.ToString()} has exception");
                EndReceive(socket, ex);
                return;
            }

            _logger.LogTrace($"UDPChannel.BeginReceive: willRaiseEvent={willRaiseEvent}");

            if (!willRaiseEvent) {
                _logger.LogTrace($"Calling UDPChannel.ProcessReceive");
                ProcessReceive(socket.ReadBuffer);
            }
        }

        private void BeginSend(UDPSocket socket, byte[] data, System.Net.EndPoint destination) {
            _logger.LogTrace($"UDPChannel.BeginSend: {socket.Socket.LocalEndPoint} ==> {destination}  #bytes={data.Length}");

            socket.SetWriteBuffer(data, 0, data.Length);
            socket.WriteBuffer.RemoteEndPoint = destination;

            bool willRaiseEvent;
            try {
                willRaiseEvent = socket.Socket.SendToAsync(socket.WriteBuffer);
            }
            catch (ObjectDisposedException) {
                // do nothing
                return;
            }
            catch (Exception ex) {
                EndSend(socket, ex);
                return;
            }

            if (!willRaiseEvent) {
                ProcessSend(socket.WriteBuffer);
            }
        }

        private void ProcessReceive(SocketAsyncEventArgs e) {
            _logger.LogTrace($"UDPChannel.ProcessReceive");

            UDPSocket socket = (UDPSocket)e.UserToken;

            if (e.SocketError == SocketError.Success) {
                _logger.LogTrace($"UDPChannel.ProcessReceive: ==> EndReceive");

                EndReceive(socket, e.Buffer, e.Offset, e.BytesTransferred, e.RemoteEndPoint);
            } else if (e.SocketError != SocketError.OperationAborted
                  && e.SocketError != SocketError.Interrupted) {

                _logger.LogTrace($"UDPChannel.ProcessRecieve: ==> exception handler {e.SocketError.ToString()}");

                EndReceive(socket, new SocketException((int)e.SocketError));
            }
        }

        private void ProcessReceiveMessageFrom(SocketAsyncEventArgs e) {
            _logger.LogTrace($"UDPChannel.ProcessReceiveMessageFrom {e.SocketError} {e.RemoteEndPoint} ==> {e.ReceiveMessageFromPacketInfo.Address}");

            UDPSocket socket = (UDPSocket)e.UserToken;

            if (e.SocketError == SocketError.Success) {
                _logger.LogTrace($"UDPChannel.ProcessReceiveMessageFrom: ==> EndReceive");

                EndReceiveMessage(socket, e.Buffer, e.Offset, e.BytesTransferred, e.RemoteEndPoint, e.ReceiveMessageFromPacketInfo.Address);
            } else if (e.SocketError != SocketError.OperationAborted
                       && e.SocketError != SocketError.Interrupted) {
                _logger.LogTrace($"UDPChannel.ProcessReceiveMessageFrom: ==> exception handler {e.SocketError.ToString()}");

                EndReceive(socket, new SocketException((int)e.SocketError));
            }
        }

        private void ProcessSend(SocketAsyncEventArgs e) {
            UDPSocket socket = (UDPSocket)e.UserToken;

            if (e.SocketError == SocketError.Success) {
                EndSend(socket, e.BytesTransferred);
            } else {
                EndSend(socket, new SocketException((int)e.SocketError));
            }
        }

        private void SocketAsyncEventArgs_Completed(object sender, SocketAsyncEventArgs e) {
            switch (e.LastOperation) {
                case SocketAsyncOperation.ReceiveMessageFrom:
                    ProcessReceiveMessageFrom(e);
                    break;

                case SocketAsyncOperation.ReceiveFrom:
                    ProcessReceive(e);
                    break;

                case SocketAsyncOperation.SendTo:
                    ProcessSend(e);
                    break;

                default:
                    _logger.LogTrace($"UDPChannel.SocketAsyncEventArgs: operation = {e.LastOperation.ToString()}");
                    break;
            }
        }

        private partial class UDPSocket
        {
            public readonly SocketAsyncEventArgs ReadBuffer;
            public readonly SocketAsyncEventArgs WriteBuffer;
            private readonly byte[] _writeBuffer;
            private bool _isOuterBuffer;

            public UDPSocket(AddressFamily addressFamily, int bufferSize,
                EventHandler<SocketAsyncEventArgs> completed) {
                Socket = new Socket(addressFamily, SocketType.Dgram, ProtocolType.Udp);
                ReadBuffer = new SocketAsyncEventArgs();
                ReadBuffer.SetBuffer(new byte[bufferSize], 0, bufferSize);
                ReadBuffer.Completed += completed;
                ReadBuffer.UserToken = this;

                _writeBuffer = new byte[bufferSize];
                WriteBuffer = new SocketAsyncEventArgs();
                WriteBuffer.SetBuffer(_writeBuffer, 0, bufferSize);
                WriteBuffer.Completed += completed;
                WriteBuffer.UserToken = this;
            }

            public void SetWriteBuffer(byte[] data, int offset, int count) {
                if (count > _writeBuffer.Length) {
                    WriteBuffer.SetBuffer(data, offset, count);
                    _isOuterBuffer = true;
                } else {
                    if (_isOuterBuffer) {
                        WriteBuffer.SetBuffer(_writeBuffer, 0, _writeBuffer.Length);
                        _isOuterBuffer = false;
                    }
                    Buffer.BlockCopy(data, offset, _writeBuffer, 0, count);
                    WriteBuffer.SetBuffer(0, count);
                }
            }

            public void Dispose() {
                Socket.Close();
                Socket.Dispose();

                ReadBuffer.Dispose();
                WriteBuffer.Dispose();
            }
        }
    }
}