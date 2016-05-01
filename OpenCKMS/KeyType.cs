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
    ///   <para>
    ///     <font size="3">There are several different types of cryptographic keys, each used for a different purpose. In addition, there is other information that is
    /// specifically related to cryptographic algorithms and keys.</font>
    ///   </para>
    ///   <para>
    ///     <font size="3">
    ///       <font size="3">Several different types of keys are defined. The keys are identified according to their classification as public, private or
    /// symmetric keys, and as to their use. For public and private key-agreement keys, their status as static or ephemeral keys is also specified.</font>
    ///     </font>
    ///   </para>
    /// </summary>
    /// <remarks>
    ///   <list type="bullet">
    ///     <item>While integrity protection is also provided, it is not the primary intention of either the public or private authentication keys.</item>
    ///     <item>In some cases ephemeral keys are used more than once, though within a single "session". For example, when Diffie-Hellman is used in S/MIME CMS, the sender
    ///     may generate one ephemeral key pair per message, and combine the private key separately with each recipient’s public key.</item>
    ///     <item>The public ephemeral key-agreement key of a sender may be retained by the receiver for later use in decrypting a stored (encrypted) message for which the
    ///     ephemeral key pair was generated</item>
    ///   </list>
    ///   <para></para>
    ///   <para>
    ///     <font size="3">Summary of Protection and Assurance Requirements for Cryptographic Keys</font>
    ///   </para>
    /// </remarks>
    /// 
    /// 
    public enum KeyType
    {
        /// <summary>
        /// Private signature keys are the private keys of asymmetric (public) 
        /// key pairs that are used by public-key algorithms to generate digital 
        /// signatures with possible long-term implications. 
        /// When properly handled, private signature keys can be used to provide 
        /// source authentication, integrity authentication and support the 
        /// non-repudiation of messages, documents or stored data.
        /// </summary>
        PrivateSignature,

        /// <summary>
        /// A public signature-verification key is the public key of an asymmetric 
        /// (public) key pair that is used by a public-key algorithm to verify digital 
        /// signatures that are intended to provide source authentication, 
        /// integrity authentication and support the non-repudiation of messages, 
        /// documents or stored data.
        /// </summary>
        PublicSignatureVerification,

        /// <summary>
        /// Symmetric authentication keys are used with symmetric-key algorithms 
        /// to provide source authentication and integrity authentication of communication 
        /// sessions, messages, documents or stored data. Note that for authenticated-encryption 
        /// modes of operation for a symmetric key algorithm, a single key is used for both 
        /// authentication and encryption.
        /// </summary>
        SymmetricAuthentication,

        /// <summary>
        /// A private authentication key is the private key of an asymmetric (public) key pair 
        /// that is used with a public-key algorithm to provide assurance of the identity of 
        /// an originating entity (i.e., source authentication) when establishing an authenticated 
        /// communication session.
        /// </summary>
        /// <remarks>While integrity protection is also provided, it is not the primary intention of this key.</remarks>
        PrivateAuthentication,

        /// <summary>
        /// A public authentication key is the public key of an asymmetric (public) key pair 
        /// that is used with a public-key algorithm to provide assurance of the identity of an originating entity 
        /// (i.e., source authentication) when establishing an authenticated communication session.
        /// </summary>
        /// <remarks>While integrity protection is also provided, it is not the primary intention of this key.</remarks>
        PublicAuthentication,

        /// <summary>
        /// These keys are used with symmetric-key algorithms to apply confidentiality protection to information 
        /// (i.e., to encrypt the information). The same key is also used to remove the confidentiality protection 
        /// (i.e., to decrypt the information). Note that for authenticated-encryption modes of operation for a 
        /// symmetric key algorithm, a single key is used for both authentication and encryption.
        /// </summary>
        SymmetricDataEncryption,

        /// <summary>
        /// Symmetric key-wrapping keys (sometimes called key-encrypting keys) are used to encrypt other keys using 
        /// symmetric-key algorithms. The key-wrapping key used to encrypt a key is also used to reverse the encryption 
        /// operation (i.e., to decrypt the encrypted key). Depending on the algorithm with which the key is used, 
        /// the key may also be used to provide integrity protection.
        /// </summary>
        SymmetricKeyWrapping,

        /// <summary>
        /// These keys are used to generate random numbers or random bits.
        /// </summary>
        SymmetricRng,

        /// <summary>
        /// These keys are used to generate random numbers or random bits.
        /// </summary>
        PrivateRng,

        /// <summary>
        /// These keys are used to generate random numbers or random bits.
        /// </summary>
        PublicRng,

        /// <summary>
        /// A symmetric master key is used to derive other symmetric keys (e.g., data-encryption keys or key-wrapping keys)  
        /// using symmetric cryptographic methods. The master key is also known as a key-derivation key.
        /// </summary>
        SymmetricMaster,

        /// <summary>
        /// Private key-transport keys are the private keys of asymmetric (public) key pairs that are used to decrypt keys 
        /// that have been encrypted with the corresponding public key using a public-key algorithm. Key-transport keys 
        /// are usually used to establish keys (e.g., key-wrapping keys, data-encryption keys or MAC keys) and, optionally, 
        /// other keying material (e.g., Initialization Vectors).
        /// </summary>
        PrivateKeyTransport,

        /// <summary>
        /// Public key-transport keys are the public keys of asymmetric (public) key pairs that are used to encrypt keys using a 
        /// public-key algorithm. These keys are used to establish keys (e.g., key-wrapping keys, data-encryption keys or MAC keys) 
        /// and, optionally, other keying material (e.g., Initialization Vectors). The encrypted form of the established key might 
        /// be stored for later decryption using the private key-transport key.
        /// </summary>
        PublicKeyTransport,

        /// <summary>
        /// These symmetric keys are used to establish keys (e.g., key-wrapping keys, data-encryption keys, or MAC keys) and, 
        /// optionally, other keying material (e.g., Initialization Vectors) using a symmetric key-agreement algorithm.
        /// </summary>
        SymmetricKeyAgreement,

        /// <summary>
        /// Private static key-agreement keys are the long-term private keys of asymmetric (public) key pairs that are used to establish 
        /// keys (e.g., key-wrapping keys, data-encryption keys, or MAC keys) and, optionally, other keying material (e.g., Initialization Vectors).
        /// </summary>
        PrivateStaticKeyAgreement,

        /// <summary>
        /// Public static key-agreement keys are the long-term public keys of asymmetric (public) key pairs that are used to establish keys 
        /// (e.g., key-wrapping keys, data-encryption keys, or MAC keys) and, optionally, other keying material (e.g., Initialization Vectors).
        /// </summary>
        PublicStaticKeyAgreement,

        /// <summary>
        /// Private ephemeral key-agreement keys are the short-term private keys of asymmetric (public) key pairs that are used only 
        /// once to establish one or more keys (e.g., key-wrapping keys, data-encryption keys, or MAC keys) and, optionally, other keying 
        /// material (e.g., Initialization Vectors).
        /// </summary>
        /// <remarks>In some cases ephemeral keys are used more than once, though within a single “session”. For example, when Diffie-Hellman 
        /// is used in S/MIME CMS, the sender may generate one ephemeral key pair per message, and combine the private key separately with each 
        /// recipient’s public key.</remarks>
        PrivateEphemeralKeyAgreement,

        /// <summary>
        /// Public ephemeral key-agreement keys are the short-term public keys of asymmetric key pairs that are used in a single key-establishment 
        /// transaction to establish one or more keys (e.g., key-wrapping keys, data-encryption keys, or MAC keys) and, optionally, other keying 
        /// material (e.g., Initialization Vectors).
        /// </summary>
        /// <remarks>The public ephemeral key-agreement key of a sender may be retained by the receiver for later use in decrypting a stored 
        /// (encrypted) message for which the ephemeral key pair was generated.</remarks>
        PublicEphemeralKeyAgreement,

        /// <summary>
        /// Symmetric authorization keys are used to provide privileges to an entity using a symmetric cryptographic method. The authorization 
        /// key is known by the entity responsible for monitoring and granting access privileges for authorized entities and by the entity 
        /// seeking access to resources.
        /// </summary>
        SymmetricAuthorization,

        /// <summary>
        /// A private authorization key is the private key of an asymmetric (public) key pair that is used to provide privileges to an entity.
        /// </summary>
        PrivateAuthorization,

        /// <summary>
        /// A public authorization key is the public key of an asymmetric (public) key pair that is used to verify privileges for an entity 
        /// that knows the associated private authorization key.
        /// </summary>
        PublicAuthorization
    }
}
