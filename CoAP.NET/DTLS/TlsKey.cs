﻿/*
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
using System.Linq;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.X509;

namespace CoAP.DTLS
{
    public class TlsKeyPair
    {
        public TlsPskIdentity PrivateKey { get; }
        public X509CertificateStructure[] X509Certificate { get; }

        public byte CertType { get; }

        /// <summary>
        /// Create a PSK version of a TLS Key Pair
        /// </summary>
        /// <param name="sharedSecret">PSK value</param>
        public TlsKeyPair(TlsPskIdentity sharedSecret) {
            this.PrivateKey = sharedSecret ?? throw new ArgumentNullException(nameof(sharedSecret));

            CertType = 0;
        }

        /// <summary>
        /// Create a TLS Key pair object for doing X.509 certificate authentication
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="privateKey"></param>
        public TlsKeyPair(byte[] certificate, TlsPskIdentity privateKey) {
            this.PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            this.X509Certificate = new X509CertificateStructure[1];
            X509Certificate[0] = new X509CertificateParser().ReadCertificate(certificate).CertificateStructure;
            CertType = (byte)CertificateType.X509; // X.509 Certificate
        }

        /// <summary>
        /// Create a TLS Key pair object with multiple X.509 certificates
        /// </summary>
        /// <param name="certificateArray"></param>
        /// <param name="privateKey"></param>
        public TlsKeyPair(X509CertificateStructure[] certificateArray, TlsPskIdentity privateKey) {
            this.PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
            this.X509Certificate = certificateArray ?? throw new ArgumentNullException(nameof(certificateArray));
            CertType = (byte)CertificateType.X509; // X.509 Certificate
        }

        public bool Compare(TlsKeyPair other) {
            if (this == other) return true;
            return false;
        }
    }

    public class TlsKeyPairSet
    {
        private readonly List<TlsKeyPair> _keyList = new List<TlsKeyPair>();

        /// <summary>
        /// Return number of keys in the key set.
        /// </summary>
        public int Count => _keyList.Count;

        /// <summary>
        /// Return first key in the set.
        /// </summary>
        public TlsKeyPair FirstKey => _keyList.First();

        /// <summary>
        /// Return the i-th element in the key set.
        /// </summary>
        /// <param name="i">index of element to return</param>
        /// <returns>OneKey</returns>
        public TlsKeyPair this[int i] => _keyList[i];

        /// <summary>
        /// Add a key to the key set.  The function will do a minimal check for equality to existing keys in the set.
        /// </summary>
        /// <param name="key">OneKey: key to be added</param>
        public void AddKey(TlsKeyPair key) {
            foreach (TlsKeyPair k in _keyList) {
                if (key.Compare(k)) {
                    return;
                }
            }
            _keyList.Add(key);
        }

        /// <summary>
        /// Allow "foreach" to be used to enumerate the keys in a key set.
        /// </summary>
        /// <returns></returns>
        public IEnumerator<TlsKeyPair> GetEnumerator() {
            return _keyList.GetEnumerator();
        }
    }
}