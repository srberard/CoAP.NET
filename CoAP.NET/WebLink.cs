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
using CoAP.Server.Resources;
using CoAP.Util;

namespace CoAP
{
    /// <summary>
    /// This class can be used to programmatically browse a remote CoAP endoint.
    /// </summary>
    public class WebLink : IComparable<WebLink>
    {
        /// <summary>
        /// Instantiates.
        /// </summary>
        /// <param name="uri">the uri of this resource.</param>
        public WebLink(String uri) {
            Uri = uri;
        }

        /// <summary>
        /// Gets the uri of this resource.
        /// </summary>
        public String Uri { get; }

        /// <summary>
        /// Gets the attributes of this resource.
        /// </summary>
        public ResourceAttributes Attributes { get; } = new ResourceAttributes();

        /// <inheritdoc/>
        public Int32 CompareTo(WebLink other) {
            if (other == null) {
                throw ThrowHelper.ArgumentNull("other");
            }

            return string.Compare(Uri, other.Uri, StringComparison.Ordinal);
        }

        /// <inheritdoc/>
        public override String ToString() {
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            sb.Append('<').Append(Uri).Append('>')
                .Append(' ').Append(Attributes.Title).Append("\n");
            foreach (string key in Attributes.Keys) {
                sb.Append("\t").Append(key).Append(":\t");
                foreach (string s in Attributes.GetValues(key)) {
                    sb.Append(s).Append(' ');
                }

                sb.Append("\n");
            }

            return sb.ToString();
        }
    }
}