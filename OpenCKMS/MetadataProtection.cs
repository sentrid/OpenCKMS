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

namespace OpenCKMS
{
    /// <summary>
    ///     This element specifies the mechanisms used to provide integrity, confidentiality, and source authentication to the
    ///     associated metadata. Generally, the same mechanism will be used to protect the key and its metadata, especially if
    ///     the key and metadata are transmitted or stored together.
    /// </summary>
    public class MetadataProtection
    {
        /// <summary>
        ///     The mechanism used for integrity protection (e.g., hash value, MAC, or digital signature).
        /// </summary>
        /// <value>The integrity mechanism.</value>
        public string IntegrityMechanism { get; set; }

        /// <summary>
        ///     The mechanism used for confidentiality protection (e.g., encryption).
        /// </summary>
        /// <value>The confidentiality mechanism.</value>
        public string ConfidentialityMechanism { get; set; }

        /// <summary>
        /// The mechanism used for source authentication.
        /// </summary>
        /// <value>The authentication mechanism.</value>
        public string AuthenticationMechanism { get; set; }

        /// <summary>
        /// An indication of the protections that are enforced by a particular non-cryptographic trusted process.
        /// </summary>
        /// <value>The non cryptographic protection.</value>
        public string NonCryptographicProtection { get; set; }
    }
}