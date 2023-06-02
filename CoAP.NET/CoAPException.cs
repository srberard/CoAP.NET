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
    public class CoAPException : Exception
    {
        public CoAPException() {
        }

        public CoAPException(string message)
            : base(message) {
        }

        public CoAPException(string message, Exception inner)
            : base(message, inner) {
        }
    }
}