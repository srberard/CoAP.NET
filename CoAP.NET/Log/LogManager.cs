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
using Microsoft.Extensions.Logging;

namespace CoAP.Log
{
    /// <summary>
    /// Log manager.
    /// </summary>
    public static class LogManager
    {
        private static ILoggerFactory _loggerFactory;

        static LogManager() {
            _loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        }

        public static void SetLoggerFactory(ILoggerFactory logger_factory) {
            _loggerFactory = logger_factory;
        }

        public static ILoggerFactory GetLoggerFactory() {
            return _loggerFactory;
        }

        /// <summary>
        /// Gets a logger of the given type.
        /// </summary>
        public static ILogger GetLogger<T>() {
            return _loggerFactory.CreateLogger<T>();
        }

        public static ILogger GetLogger(Type T) {
            return _loggerFactory.CreateLogger(T);
        }
    }
}