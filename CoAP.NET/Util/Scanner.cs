﻿/*
 * Copyright (c) 2011-2012, Longxiang He <helongxiang@smeshlink.com>,
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
using System.Text.RegularExpressions;

namespace CoAP.Util
{
    internal class Scanner
    {
        private String _s;
        private Int32 _position;

        public Scanner(String s) {
            _s = s;
            _position = 0;
        }

        public bool EndOfString {
            get => _position >= _s.Length;
        }

        public void Advance() {
            _position += 1;
        }

        public bool CharIs(char ch) {
            if (EndOfString) return false;
            return ch == _s[_position];
        }

        public String Find(Regex regex) {
            return Find(regex, -1);
        }

        public String Find(Regex regex, Int32 horizon) {
            if (_position < _s.Length) {
                Match m = horizon < 0 ? regex.Match(_s, _position) : regex.Match(_s, _position, horizon);
                if (m.Success) {
                    _position = m.Index + m.Length;
                    return m.Value;
                }
            }

            return null;
        }
    }
}