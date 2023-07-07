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
using System.Text;
using CoAP.Log;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace CoAP.DTLS
{
    public class DTLSServer : DefaultTlsServer //PskTlsServer
    {
        private static readonly ILogger _logger = LogManager.GetLogger<DTLSServer>();
        private readonly TlsKeyPairSet _serverKeys;
        private TlsPskKeySet _userKeys;
        private readonly PskIdentityManager _pskIdentityMgr;
        public EventHandler<TlsEvent> TlsEventHandler;

        //public KeySet CwtTrustKeySet { get; set; }
        private static readonly int[] SupportedCipherSuites = new int[] {
            CipherSuite.TLS_PSK_WITH_AES_128_CCM,
            CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
            CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256
        };

        public DTLSServer(TlsKeyPairSet serverKeys, TlsPskKeySet userKeys) : base(new BcTlsCrypto()) {
            _serverKeys = serverKeys;
            _userKeys = userKeys;
            _pskIdentityMgr = new PskIdentityManager(userKeys);
            _pskIdentityMgr.TlsEventHandler += OnTlsEvent;
        }

        protected override ProtocolVersion[] GetSupportedVersions() {
            return ProtocolVersion.DTLSv12.Only();
        }

        public TlsPskIdentity AuthenticationKey => _pskIdentityMgr.AuthenticationKey;
        public Certificate AuthenticationCertificate { get; private set; }

        // Chain all of our events to the next level up.

        private void OnTlsEvent(Object o, TlsEvent e) {
            EventHandler<TlsEvent> handler = TlsEventHandler;
            if (handler != null) {
                handler(o, e);
            }
        }

        protected override int[] GetSupportedCipherSuites() {
            return TlsUtilities.GetSupportedCipherSuites(Crypto, SupportedCipherSuites);
        }

        public override void NotifyFallback(bool isFallback) {
            _logger.LogTrace($"Called:  NotifyFallback {isFallback}");
            base.NotifyFallback(isFallback);
        }

        public override void NotifySecureRenegotiation(bool secureRenegotiation) {
            _logger.LogTrace($"Called:  NotifySecureRenegotiation {secureRenegotiation} ");
            base.NotifySecureRenegotiation(secureRenegotiation);
        }

        public override void NotifyHandshakeBeginning() {
            _logger.LogTrace($"Called:  NotifyHandshakeBeginning");
            base.NotifyHandshakeBeginning();
        }

        public override void NotifyHandshakeComplete() {
            _logger.LogTrace($"Called:  NotifyHandshakeComplete");
            base.NotifyHandshakeComplete();
        }

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause) {
            _logger.LogTrace($"Called:  NotifyAlertRaised {alertDescription} : {message} ");
            base.NotifyAlertRaised(alertLevel, alertDescription, message, cause);
        }

        public override TlsCredentials GetCredentials() {
            int keyExchangeAlgorithm = m_context.SecurityParameters.KeyExchangeAlgorithm;

            switch (keyExchangeAlgorithm) {
                case KeyExchangeAlgorithm.DHE_PSK:
                case KeyExchangeAlgorithm.ECDHE_PSK:
                case KeyExchangeAlgorithm.PSK:
                    return null;

                case KeyExchangeAlgorithm.RSA_PSK:
                    return GetRsaEncryptionCredentials();

                default:
                    // Note: internal error here; selected a key exchange we don't implement!
                    throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public override TlsPskIdentityManager GetPskIdentityManager() {
            return _pskIdentityMgr;
        }

        public override void NotifyClientCertificate(Certificate clientCertificate) {
            TlsEvent e = new TlsEvent(TlsEvent.EventCode.ClientCertificate) {
                Certificate = clientCertificate
            };

            EventHandler<TlsEvent> handler = TlsEventHandler;
            if (handler != null) {
                handler(this, e);
            }

            if (!e.Processed) {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
            }

            //TOD:  Fix  AuthenticationCertificate = (Certificate)clientCertificate;
        }

        internal class PskIdentityManager
            : TlsPskIdentityManager
        {
            private TlsPskKeySet _userKeys;
            public EventHandler<TlsEvent> TlsEventHandler;

            internal PskIdentityManager(TlsPskKeySet keys) {
                _userKeys = keys;
            }

            public TlsPskIdentity AuthenticationKey { get; private set; }

            public virtual byte[] GetHint() {
                return Encoding.UTF8.GetBytes("hint");
            }

            public virtual byte[] GetPsk(byte[] identity) {
                var psk = _userKeys.GetKey(identity);

                if (psk != null) {
                    AuthenticationKey = psk;
                    return ((byte[])psk.GetPsk().Clone());
                }

                // Lookup the key based on the identity

                // TODO:  Setup proper key resolution eventing
                TlsEvent e = new TlsEvent(TlsEvent.EventCode.UnknownPskName) {
                    PskName = identity
                };

                EventHandler<TlsEvent> handler = TlsEventHandler;
                if (handler != null) {
                    handler(this, e);
                }

                if (e.KeyValue != null) {
                    AuthenticationKey = e.KeyValue;
                    return (e.KeyValue.GetPsk());
                }

                return null;
            }

            public void GetCertKey(Certificate certificate) {
            }
        }
    }
}