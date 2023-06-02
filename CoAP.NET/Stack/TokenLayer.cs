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
using CoAP.Log;
using CoAP.Net;
using Microsoft.Extensions.Logging;

namespace CoAP.Stack
{
    /// <summary>
    /// Doesn't do much yet except for setting a simple token. Notice that empty
    /// tokens must be represented as byte array of length 0 (not null).
    /// </summary>
    public class TokenLayer : AbstractLayer
    {
        private static ILogger _logger = LogManager.GetLogger<TokenLayer>();

        /// <summary>
        /// Constructs a new token layer.
        /// </summary>
        public TokenLayer(ICoapConfig config) {
        }

        /// <inheritdoc/>
        public override void SendResponse(INextLayer nextLayer, Exchange exchange, Response response) {
            // A response must have the same token as the request it belongs to. If
            // the token is empty, we must use a byte array of length 0.
            if (response.Token == null) {
                response.Token = exchange.CurrentRequest.Token;
            }
            base.SendResponse(nextLayer, exchange, response);
        }

        /// <inheritdoc/>
        public override void ReceiveRequest(INextLayer nextLayer, Exchange exchange, Request request) {
            if (exchange.CurrentRequest.Token == null) {
                _logger.LogInformation("ReceiveRequest: Received request token cannot be null");
                throw new InvalidOperationException("Received requests's token cannot be null, use byte[0] for empty tokens");
            }
            base.ReceiveRequest(nextLayer, exchange, request);
        }

        /// <inheritdoc/>
        public override void ReceiveResponse(INextLayer nextLayer, Exchange exchange, Response response) {
            if (response.Token == null) {
                _logger.LogInformation("ReceiveResponse: Received response token cannot be null");
                throw new InvalidOperationException("Received response's token cannot be null, use byte[0] for empty tokens");
            }
            base.ReceiveResponse(nextLayer, exchange, response);
        }
    }
}