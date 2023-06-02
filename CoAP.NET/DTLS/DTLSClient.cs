/*
 * Copyright (c) 2023-, Stephen Berard <stephen.berard@outlook.com>
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY.
 * This file is part of the CoAP.NET, a CoAP framework in C#.
 * Please see README for more information.
 */

using System;
using System.Collections.Generic;
using CoAP.Log;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;
using PeterO.Cbor;

namespace CoAP.DTLS
{
    public class DtlsClient : DefaultTlsClient
    {
        private static readonly ILogger _logger = LogManager.GetLogger<DtlsClient>();
        private readonly TlsPskIdentity _pskIdentity;
        private TlsSession _Session;
        public EventHandler<TlsEvent> TlsEventHandler;
        private readonly TlsKeyPair _tlsKeyPair;

        private static readonly int[] SupportedCipherSuites = new int[] {
            CipherSuite.TLS_PSK_WITH_AES_128_CCM,
            CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
            CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256
        };

        public DtlsClient(TlsSession session, TlsPskIdentity pskIdentity) : base(new BcTlsCrypto()) {
            _Session = session;
            _pskIdentity = pskIdentity;
        }

        protected override ProtocolVersion[] GetSupportedVersions() {
            return ProtocolVersion.DTLSv12.Only();
        }

        protected override int[] GetSupportedCipherSuites() {
            return TlsUtilities.GetSupportedCipherSuites(Crypto, SupportedCipherSuites);
        }

        public override TlsPskIdentity GetPskIdentity() {
            return _pskIdentity;
        }

        /// <summary>
        /// Decide which type of client and server certificates are going to be supported.
        /// By default, we assume that only those certificate types which match the clients
        /// certificate are going to be supported for the server.
        /// </summary>
        /// <returns></returns>
        public override IDictionary<int, byte[]> GetClientExtensions() {
            var clientExtensions = TlsExtensionsUtilities.EnsureExtensionsInitialised(base.GetClientExtensions());

            // TlsExtensionsUtilities.AddEncryptThenMacExtension(clientExtensions);
            // TlsExtensionsUtilities.AddExtendedMasterSecretExtension(clientExtensions);
            {
                /*
                 * NOTE: If you are copying test code, do not blindly set these extensions in your own client.
                 */
                //   TlsExtensionsUtilities.AddMaxFragmentLengthExtension(clientExtensions, MaxFragmentLength.pow2_9);
                //    TlsExtensionsUtilities.AddPaddingExtension(clientExtensions, mContext.SecureRandom.Next(16));
                //    TlsExtensionsUtilities.AddTruncatedHMacExtension(clientExtensions);
            }

            TlsEvent e = new TlsEvent(TlsEvent.EventCode.GetExtensions) {
                Dictionary = clientExtensions
            };

            EventHandler<TlsEvent> handler = TlsEventHandler;
            if (handler != null) {
                handler(this, e);
            }

            return e.Dictionary;
        }

        public override TlsAuthentication GetAuthentication() {
            if (_tlsKeyPair != null && _tlsKeyPair.CertType == CertificateType.X509) {
                MyTlsAuthentication auth = new MyTlsAuthentication(m_context, _tlsKeyPair);
                auth.TlsEventHandler += MyTlsEventHandler;
                return auth;
            }

            throw new CoAPException("ICE");
        }

        private void MyTlsEventHandler(object sender, TlsEvent tlsEvent) {
            EventHandler<TlsEvent> handler = TlsEventHandler;
            if (handler != null) {
                handler(sender, tlsEvent);
            }
        }

        private static BigInteger ConvertBigNum(CBORObject cbor) {
            byte[] rgb = cbor.GetByteString();
            byte[] rgb2 = new byte[rgb.Length + 2];
            rgb2[0] = 0;
            rgb2[1] = 0;
            for (int i = 0; i < rgb.Length; i++) {
                rgb2[i + 2] = rgb[i];
            }

            return new BigInteger(rgb2);
        }

        protected TlsCredentialedSigner GetECDsaSignerCredentials() {
            TlsEvent e = new TlsEvent(TlsEvent.EventCode.SignCredentials) {
                CipherSuite = KeyExchangeAlgorithm.ECDH_ECDSA
            };

            EventHandler<TlsEvent> handler = TlsEventHandler;
            if (handler != null) {
                handler(this, e);
            }

            if (e.SignerCredentials != null) return e.SignerCredentials;
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        /// <summary>
        /// We don't care if we cannot do secure renegotiation at this time.
        /// This needs to be reviewed in the future M00TODO
        /// </summary>
        /// <param name="secureRenegotiation"></param>
        public override void NotifySecureRenegotiation(bool secureRenegotiation) {
            //  M00TODO - should we care?
        }

        internal class MyTlsAuthentication
            : TlsAuthentication
        {
            private readonly TlsContext _mContext;
            public EventHandler<TlsEvent> TlsEventHandler;
            private TlsKeyPair TlsKey { get; set; }

            internal MyTlsAuthentication(TlsContext context, TlsKeyPair rawPublicKey) {
                this._mContext = context;
                TlsKey = rawPublicKey;
            }

            public TlsPskIdentity AuthenticationKey { get; private set; }

            public virtual void NotifyServerCertificate(TlsServerCertificate serverCertificate) {
                TlsEvent e = new TlsEvent(TlsEvent.EventCode.ServerCertificate) {
                    Certificate = serverCertificate.Certificate,
                    CertificateType = CertificateType.X509
                };

                EventHandler<TlsEvent> handler = TlsEventHandler;
                if (handler != null) {
                    handler(this, e);
                }

                if (!e.Processed) {
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);
                }
            }

            private BigInteger ConvertBigNum(CBORObject cbor) {
                byte[] rgb = cbor.GetByteString();
                byte[] rgb2 = new byte[rgb.Length + 2];
                rgb2[0] = 0;
                rgb2[1] = 0;
                for (int i = 0; i < rgb.Length; i++) {
                    rgb2[i + 2] = rgb[i];
                }

                return new BigInteger(rgb2);
            }

            public virtual TlsCredentials GetClientCredentials(CertificateRequest certificateRequest) {
                if (certificateRequest.CertificateTypes == null ||
                    !Arrays.Contains(certificateRequest.CertificateTypes, ClientCertificateType.ecdsa_sign)) {
                    return null;
                }

                //if (TlsKey != null) {
                //    if (TlsKey.CertType == CertificateType.X509) {
                //        return new DefaultTlsSignerCredentials(_mContext, new Certificate(TlsKey.X509Certificate), TlsKey.PrivateKey.AsPrivateKey(),
                //            new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa));
                //    }
                //}

                // If we did not fine appropriate signer credentials - ask for help

                TlsEvent e = new TlsEvent(TlsEvent.EventCode.SignCredentials) {
                    CipherSuite = KeyExchangeAlgorithm.ECDHE_ECDSA
                };

                EventHandler<TlsEvent> handler = TlsEventHandler;
                if (handler != null) {
                    handler(this, e);
                }

                if (e.SignerCredentials != null) return e.SignerCredentials;
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
    }
}