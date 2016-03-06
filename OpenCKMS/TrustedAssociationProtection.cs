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
    ///     This information is implicitly provided if the key and metadata are protected as one aggregated item using the
    ///     protection listed in <see cref="KeyMetadata" />. Otherwise, the properties in this class should be provided for
    ///     each trusted association protection.
    /// </summary>
    public class TrustedAssociationProtection
    {
        /// <summary>
        ///     The mechanism used for integrity protection (e.g., hash value, MAC, digital signature, or trusted process).
        /// </summary>
        /// <value>The integrity protection mechanism.</value>
        public string IntegrityProtectionMechanism { get; set; }

        /// <summary>
        ///     The mechanism used for source authentication (e.g., cryptographic mechanism or non-cryptographic trusted process).
        /// </summary>
        /// <value>The authentication mechanism.</value>
        public string AuthenticationMechanism { get; set; }
    }
}