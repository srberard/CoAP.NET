﻿/*
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
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace CoAP.Server.Resources
{
    /// <summary>
    /// Wraps different attributes that the CoAP protocol defines
    /// such as title, resource type or interface description. These attributes will
    /// also be included in the link description of the resource they belong to. For
    /// example, if a title was specified, the link description for a sensor resource
    /// might look like this <code>&lt;/sensors&gt;;title="Sensor Index"</code>.
    /// </summary>
    public class ResourceAttributes
    {
        private static readonly IEnumerable<String> _Empty = new String[0];

        private readonly ConcurrentDictionary<String, ICollection<String>> _attributes
            = new ConcurrentDictionary<String, ICollection<String>>();

        /// <summary>
        /// Gets the number of attributes.
        /// </summary>
        public Int32 Count {
            get => _attributes.Count;
        }

        /// <summary>
        /// Gets all the attribute names.
        /// </summary>
        public IEnumerable<String> Keys {
            get => _attributes.Keys;
        }

        /// <summary>
        /// Gets the resource title.
        /// </summary>
        public String Title {
            get => FirstOrDefault(GetValues(LinkFormat.Title));
            set => Set(LinkFormat.Title, value);
        }

        /// <summary>
        /// Gets or sets a value indicating if the resource is observable.
        /// </summary>
        public Boolean Observable {
            get => !IsEmpty(GetValues(LinkFormat.Observable));
            set {
                if (value) {
                    Set(LinkFormat.Observable, String.Empty);
                } else {
                    Clear(LinkFormat.Observable);
                }
            }
        }

        /// <summary>
        /// Gets or sets the maximum size estimate.
        /// </summary>
        public Int32 MaximumSizeEstimate {
            get {
                String value = MaximumSizeEstimateString;
                return String.IsNullOrEmpty(value) ? 0 : Int32.Parse(value);
            }
            set => MaximumSizeEstimateString = value.ToString();
        }

        /// <summary>
        /// Gets or sets the maximum size estimate.
        /// </summary>
        public String MaximumSizeEstimateString {
            get => FirstOrDefault(GetValues(LinkFormat.MaxSizeEstimate));
            set => Set(LinkFormat.MaxSizeEstimate, value);
        }

        /// <summary>
        /// Adds a resource type.
        /// </summary>
        public void AddResourceType(String type) {
            FindValues(LinkFormat.ResourceType).Add(type);
        }

        /// <summary>
        /// Gets all resource types.
        /// </summary>
        public IEnumerable<String> GetResourceTypes() {
            return GetValues(LinkFormat.ResourceType);
        }

        /// <summary>
        /// Clears all resource types.
        /// </summary>
        public void ClearResourceTypes() {
            Clear(LinkFormat.ResourceType);
        }

        /// <summary>
        /// Adds an interface description.
        /// </summary>
        public void AddInterfaceDescription(String description) {
            FindValues(LinkFormat.InterfaceDescription).Add(description);
        }

        /// <summary>
        /// Gets all interface descriptions.
        /// </summary>
        public IEnumerable<String> GetInterfaceDescriptions() {
            return GetValues(LinkFormat.InterfaceDescription);
        }

        /// <summary>
        /// Clears all interface descriptions.
        /// </summary>
        public void ClearInterfaceDescriptions() {
            Clear(LinkFormat.InterfaceDescription);
        }

        /// <summary>
        /// Adds a content type specified by an integer.
        /// </summary>
        public void AddContentType(Int32 type) {
            FindValues(LinkFormat.ContentType).Add(type.ToString());
        }

        /// <summary>
        /// Gets all content types.
        /// </summary>
        public IEnumerable<String> GetContentTypes() {
            return GetValues(LinkFormat.ContentType);
        }

        /// <summary>
        /// Clears all content types.
        /// </summary>
        public void ClearContentTypes() {
            Clear(LinkFormat.ContentType);
        }

        /// <summary>
        /// Returns <tt>true</tt> if this object contains the specified attribute.
        /// </summary>
        public Boolean Contains(String name) {
            return _attributes.ContainsKey(name);
        }

        /// <summary>
        /// Adds an arbitrary attribute with no value.
        /// </summary>
        public void Add(String name) {
            Add(name, String.Empty);
        }

        /// <summary>
        /// Adds the specified value to the other values of the specified attribute.
        /// </summary>
        public void Add(String name, String value) {
            FindValues(name).Add(value);
        }

        /// <summary>
        /// Replaces the value for the specified attribute with the specified value.
        /// If another value has been set for the attribute name, it will be removed.
        /// </summary>
        public void Set(String name, String value) {
            SetOnly(FindValues(name), value);
        }

        /// <summary>
        /// Gets all values for the specified attribute.
        /// </summary>
        public IEnumerable<String> GetValues(String name) {
            ICollection<String> values;
            return _attributes.TryGetValue(name, out values) ? values : _Empty;
        }

        /// <summary>
        /// Removes all values for the specified attribute.
        /// </summary>
        public void Clear(String name) {
            ICollection<String> values;
            _attributes.TryRemove(name, out values);
        }

        private ICollection<String> FindValues(String name) {
            return _attributes.GetOrAdd(name, key => {
                List<String> list = new List<String>();
                return new SynchronizedCollection<String>(((ICollection)list).SyncRoot, list, false);
            });
        }

        private static Boolean IsEmpty(IEnumerable<String> values) {
            // ReSharper disable once UnusedVariable
            foreach (String item in values) {
                return false;
            }
            return true;
        }

        private static String FirstOrDefault(IEnumerable<String> values) {
            foreach (String item in values) {
                return item;
            }
            return null;
        }

        private static void SetOnly(ICollection<String> values, String value) {
            lock (((ICollection)values).SyncRoot) {
                values.Clear();
                if (value != null) {
                    values.Add(value);
                }
            }
        }
    }
}