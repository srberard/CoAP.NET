/*
 * Copyright (c) 2023-, Stephen Berard <stephen.berard@outlook.com>
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY.
 *
 * This file is part of the CoAP.NET, a CoAP framework in C#.
 * Please see README for more information.
 */

using System.Text;
using CoAP.Util;
using PeterO.Cbor;

namespace CoAP.Coral
{
    public abstract class CoralItem
    {
        public abstract CBORObject EncodeToCBORObject(Cori baseCori, CoralDictionary dictionary);

        public abstract void BuildString(StringBuilder builder, string pad, Cori contextCori, CoralUsing usingDictionary);

        public static bool IsLiteral(CBORObject value) {
            if (value.IsTagged) {
                return value.HasOneTag(1) && value.Type == CBORType.Integer;
            }

            switch (value.Type) {
                case CBORType.Integer:
                case CBORType.Boolean:
                case CBORType.FloatingPoint:
                case CBORType.ByteString:
                case CBORType.TextString:
                    return true;

                case CBORType.SimpleValue:
                    return value.IsNull;

                case CBORType.Array: // CoRI
                    return false;

                default:
                    return false;
            }
        }
    }
}