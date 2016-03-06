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
    ///     This element specifies the integrity, confidentiality, and source authentication protections applied to the key. A
    ///     public key certificate is an example of key protection whereby the CA’s digital signature provides both the
    ///     integrity protection and source authentication (see [X.509]). A symmetric key and its hash value encrypted together
    ///     is an example of confidentiality and integrity protection. When a key and its metadata are received from an
    ///     external entity, the protections should be verified before the key and metadata are operationally used. Generally,
    ///     a single cryptographic function (e.g., HMAC or digital signature) is used to provide both integrity protection and
    ///     source authentication.
    /// </summary>
    public class KeyProtection
    {
        /// <summary>
        ///     The mechanism used for integrity protection (e.g., hash value, MAC, or digital signature).
        /// </summary>
        /// <value>The integrity mechanism.</value>
        public string IntegrityMechanism { get; set; }

        /// <summary>
        ///     The mechanism used for confidentiality protection (e.g., key wrapping or key transport).
        /// </summary>
        /// <value>The confidentiality mechanism.</value>
        public string ConfidentialityMechanism { get; set; }

        /// <summary>
        ///     The mechanism used for source authentication (e.g., MAC or digital signature).
        /// </summary>
        /// <value>The authentication mechanism.</value>
        public string AuthenticationMechanism { get; set; }

        /// <summary>
        ///     An indication of the protections that are enforced by a particular non-cryptographic trusted process.
        /// </summary>
        /// <value>The non cryptographic protection.</value>
        public string NonCryptographicProtection { get; set; }
    }
}