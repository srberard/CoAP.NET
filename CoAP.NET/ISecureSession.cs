/*
 * Copyright (c) 2023-, Stephen Berard <stephen.berard@outlook.com>
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY.
 *
 * This file is part of the CoAP.NET, a CoAP framework in C#.
 * Please see README for more information.
 */

using Org.BouncyCastle.Tls;

namespace CoAP
{
    public interface ISecureSession : ISession
    {
        TlsPskIdentity AuthenticationKey { get; }
        Certificate AuthenticationCertificate { get; }
    }
}