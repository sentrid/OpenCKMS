// Copyright 2016 Edward Curren
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;

namespace OpenCKMS
{
    /// <summary>
    ///     The important date-times in the lifecycle state transitions of a key. The dates and times used in the metadata
    ///     elements, as well as various CKMS transaction dates and times, may be required to be both accurate and
    ///     from an authoritative source, such as a Network Time Protocol (NTP) server. In addition, some of the transactions
    ///     may require time stamps from a trusted third-party.
    /// </summary>
    public class EventEpochs
    {
        /// <summary>
        ///     The date-time that a key was generated.
        /// </summary>
        /// <value>The key generated.</value>
        public DateTime KeyGenerated { get; set; }

        /// <summary>
        ///     The date-time that a key was associated with its metadata for the first time.
        /// </summary>
        /// <value>The metadata association.</value>
        public DateTime MetadataAssociation { get; set; }

        /// <summary>
        ///     The date-time that a key was first used.
        /// </summary>
        /// <value>The activation.</value>
        public DateTime Activation { get; set; }

        /// <summary>
        ///     The date-time that a key is first to be used.
        /// </summary>
        /// <value>The future activation.</value>
        public DateTime FutureActivation { get; set; }

        /// <summary>
        ///     The date-time that a public key was renewed and allowed to be used for a longer period of time, e.g., by generating
        ///     a new certificate for the same public key as was provided in an old certificate.
        /// </summary>
        /// <value>The renewed.</value>
        public DateTime Renewed { get; set; }

        /// <summary>
        ///     The future renewal data: The date-time that a public key is to be renewed and allowed to be used for a longer
        ///     period of time (e.g., by generating a new certificate for the same public key as was provided in an old
        ///     certificate).
        /// </summary>
        /// <value>The future renewal.</value>
        public DateTime FutureRenewal { get; set; }

        /// <summary>
        ///     The date-time that a key was replaced with a new key that was generated so that it is completely independent of the
        ///     key that was replaced.
        /// </summary>
        /// <value>The last re key.</value>
        public DateTime LastReKey { get; set; }

        /// <summary>
        ///     The date-time that the key is to be replaced with a new key that will be generated so that it is completely
        ///     independent of the key being replaced.
        /// </summary>
        /// <value>The future re key.</value>
        public DateTime FutureReKey { get; set; }

        /// <summary>
        ///     The date of the last usage of the key: The date-time that the key was last used.
        /// </summary>
        /// <value>The last used.</value>
        public DateTime LastUsed { get; set; }

        /// <summary>
        ///     The date-time that a key was deactivated.
        /// </summary>
        /// <value>The deactivated.</value>
        public DateTime Deactivated { get; set; }

        /// <summary>
        ///     The date-time that a key is to be deactivated.
        /// </summary>
        /// <value>The future deactivation.</value>
        public DateTime FutureDeactivation { get; set; }

        /// <summary>
        ///     The date-time that a key’s useful lifetime was terminated permanently.
        /// </summary>
        /// <value>The expires.</value>
        public DateTime Expired { get; set; }

        /// <summary>
        ///     The date-time after which a key was no longer considered valid.
        /// </summary>
        /// <value>The revoke.</value>
        public DateTime Revoked { get; set; }

        /// <summary>
        ///     The date-time that a key was known or suspected to have been compromised and was marked for replacement and not
        ///     renewal.
        /// </summary>
        /// <value>The compromised.</value>
        public DateTime Compromised { get; set; }

        /// <summary>
        ///     The date-time that a key was destroyed.
        /// </summary>
        /// <value>The destroyed.</value>
        public DateTime Destroyed { get; set; }

        /// <summary>
        ///     The date-time that a key is to be destroyed.
        /// </summary>
        /// <value>The destroy.</value>
        public DateTime Destroy { get; set; }
    }
}