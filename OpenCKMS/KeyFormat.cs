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


// ReSharper disable InconsistentNaming

namespace OpenCKMS
{
    /// <summary>
    ///     Enum KeyFormat
    /// </summary>
    public enum KeyFormat
    {
        /// <summary>
        ///     The RSA
        /// </summary>
        RSA,

        /// <summary>
        ///     The rsass a PSS
        /// </summary>
        RSASSA_PSS,

        /// <summary>
        ///     The rsae s_ oaep
        /// </summary>
        RSAES_OAEP,

        /// <summary>
        ///     The DSA
        /// </summary>
        DSA,

        /// <summary>
        ///     The ecdsa
        /// </summary>
        ECDSA,

        /// <summary>
        ///     The ecdh
        /// </summary>
        ECDH,

        /// <summary>
        ///     The sh a_1
        /// </summary>
        SHA_1,

        /// <summary>
        ///     The sh a_224
        /// </summary>
        SHA_224,

        /// <summary>
        ///     The sh a_256
        /// </summary>
        SHA_256,

        /// <summary>
        ///     The sh a_384
        /// </summary>
        SHA_384,

        /// <summary>
        ///     The sh a_512
        /// </summary>
        SHA_512,

        /// <summary>
        ///     The sec P192 r1
        /// </summary>
        SECP192R1,

        /// <summary>
        ///     The sec P224 r1
        /// </summary>
        SECP224R1,

        /// <summary>
        ///     The sec P256 r1
        /// </summary>
        SECP256R1,

        /// <summary>
        ///     The sec P384 r1
        /// </summary>
        SECP384R1,

        /// <summary>
        ///     The sec P521 r1
        /// </summary>
        SECP521R1,

        /// <summary>
        /// The sec P163 r2
        /// </summary>
        SECP163R2,

        /// <summary>
        ///     The sec T163 k1
        /// </summary>
        SECT163K1,

        /// <summary>
        /// The sec T283 r1
        /// </summary>
        SECT283R1,

        /// <summary>
        /// The sec T283 k1
        /// </summary>
        SECT283K1,

        /// <summary>
        /// The sec T233 r1
        /// </summary>
        SECT233R1,

        /// <summary>
        /// The sec T233 k1
        /// </summary>
        SECT233K1,

        /// <summary>
        /// The sec T409K k1
        /// </summary>
        SECT409kK1,

        /// <summary>
        /// The sec T409K r1
        /// </summary>
        SECT409kR1,

        /// <summary>
        /// The sec T571 k1
        /// </summary>
        SECT571K1,

        /// <summary>
        /// The sec T571 r1
        /// </summary>
        SECT571R1
    }
}