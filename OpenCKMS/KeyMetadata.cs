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
using System.Collections.Generic;

namespace OpenCKMS
{
    /// <summary>
    ///     Class KeyMetadata.
    /// </summary>
    public class KeyMetadata
    {
        /// <summary>
        ///     A key label is a text string that provides a human-readable,
        ///     and perhaps machine-readable, set of descriptors for the key.
        ///     Examples of key labels include: “Root CA Private Key 2009-29”
        ///     and “Maintenance Secret Key 2005.”
        /// </summary>
        /// <value>The key label.</value>
        public string Label { get; set; }

        /// <summary>
        ///     This element is used by the CKMS to select a specific key
        ///     from a collection of keys. A key identifier is generally
        ///     unique in a security domain. For public and private keys, a key
        ///     identifier can be a hash value or portion of the hash value of
        ///     the public key or can be assigned by the CKMS.
        /// </summary>
        /// <value>The key identifier.</value>
        public Guid Identifier { get; set; }

        /// <summary>
        ///     This element specifies the identifier (or identifiers) of
        ///     the entity (or entities) that owns (or own) the key.
        /// </summary>
        /// <value>The owner identifier.</value>
        public Guid OwnerId { get; set; }

        /// <summary>
        ///     A key lifecycle state is one of a set of finite states that
        ///     describe the current permitted conditions of a cryptographic key.
        /// </summary>
        /// <value>The state of the key lifecycle.</value>
        public KeyLifecycleState KeyLifecycleState { get; set; }

        /// <summary>
        ///     This element is used to specify the format for the key.
        ///     This can be accomplished by reference to the structure using
        ///     object identifiers. For example, an RSA public key consists of
        ///     the modulus and a public exponent. The format specifier should
        ///     specify the sequence in which these two values are stored and
        ///     the format in which each value is encoded.
        ///     The Internet Engineering Task Force (IETF) has defined an object
        ///     identifier for storing different forms of public keys, such as
        ///     DSA, DH, RSA, EC, RSAPSS, and RSAOAEP keys.
        /// </summary>
        /// <value>The format of the key.</value>
        public KeyFormat Format { get; set; }

        /// <summary>
        ///     This element specifies which cryptographic product was used to
        ///     create or generate the key.
        /// </summary>
        public string KeyCreatedBy => "OpenCKMS";

        /// <summary>
        ///     This element specifies the cryptographic algorithm that is intended
        ///     to use the key. Examples include DSA, ECDSA, RSA, AES, TDEA, and HMAC-SHA1.
        /// </summary>
        /// <value>The target algorithm.</value>
        public string TargetAlgorithm { get; set; }

        /// <summary>
        ///     This element defines the applicable schemes or modes of operation for performing
        ///     a cryptographic function using a key. For asymmetric algorithms, it may specify
        ///     the operation of discrete logarithm algorithms in a mathematical finite field,
        ///     binary field, or Elliptic Curve (EC) field. For symmetric algorithms, this field
        ///     may define the mode(s) of operation that can be used by the block cipher algorithm
        ///     when using the key. Examples of modes of operation are Electronic Code Book (ECB),
        ///     Cipher Block Chaining (CBC), Output Feedback Mode (OFB), and Counter with Cipher Block
        ///     Chaining-Message Authentication Mode (CCM).
        /// </summary>
        /// <value>The mode of operation.</value>
        public string ModeOfOperation { get; set; }


        /// <summary>
        ///     This element specifies the parameters, if applicable, for a key. For example,
        ///     a DSA key has the following domain parameters: large prime (p), small prime (q),
        ///     and generator (g).
        /// </summary>
        /// <value>Key parameters.</value>
        public List<string> Parameters { get; set; }

        /// <summary>
        ///     This element specifies the length of the key in bits (or bytes). Examples include 2048 bits
        ///     for an RSA modulus, and 256 bits for an elliptic curve key.
        /// </summary>
        /// <value>The length.</value>
        public int Length { get; set; }

        /// <summary>
        ///     This element is a number indicating the amount of work
        ///     (that is, the base 2 logarithm of the number of operations) that is required to break
        ///     (i.e., crypt analyze) the cryptographic algorithm. For example, for a TDEA key of 168 bits
        ///     (not including parity bits), the security strength is specified as 112 bits; for a 2048-bit
        ///     RSA modulus, the security strength is specified as 112 bits. The security strength of a
        ///     key/algorithm pair may be reduced if a previously unknown attack is discovered.
        /// </summary>
        /// <value>The strength.</value>
        public int Strength { get; set; }

        /// <summary>
        ///     This element identifies the key type.
        /// </summary>
        /// <value>The type of the key.</value>
        public KeyType KeyType { get; set; }

        /// <summary>
        ///     This element specifies applications for which the key may be used. Examples include
        ///     Kerberos, Signed E-Mail, Trusted Time Stamp, Code Signing, File Encryption, and IPSEC.
        /// </summary>
        /// <value>The appropriate applications.</value>
        public List<string> AppropriateApplications { get; set; }

        /// <summary>
        ///     This element identifies the security policy applicable to the key or key type.
        ///     A Key Security Policy is a set of security controls that are used to protect the key or
        ///     key type during the lifecycle of the key from generation to destruction. A Key Security
        ///     Policy is typically represented by an object identifier registered by the CKMS organization.
        ///     The Key Security Policy for individual keys or key types is part of, and should be
        ///     consistent with, the CKMS Security Policy.
        /// </summary>
        /// <value>The security policy identifier.</value>
        public string SecurityPolicyId { get; set; }

        /// <summary>
        ///     An access control list identifies the entities that can access and/or use the keys as
        ///     constrained by the key and metadata management functions (see Section 6.7). This Framework
        ///     does not specify the access control list structure. The following are examples of such
        ///     structures: a Microsoft Windows file/folder access control list consisting of zero or more
        ///     access control entries, a Sun File System access control list, and while not a list, the Unix
        ///     protection bits. In cases where interoperability is desired, the following items may require
        ///     standardization: the syntax and semantics of the separators among access control entries, the
        ///     ordering of entity and “access modes” within an access control entry, the entity identifier,
        ///     and the designation of bits for different “access modes”. If required for interoperability,
        ///     these items should be included in an appropriately detailed design specification.
        /// </summary>
        /// <value>The access control list.</value>
        public List<string> AccessControlList { get; set; }

        /// <summary>
        ///     This element indicates the number of times that the key has been used.
        /// </summary>
        /// <value>The use count.</value>
        public int UseCount { get; set; }

        /// <summary>
        ///     This element points to the key from which the key associated with this metadata is derived.
        ///     For example, a new key (i.e., the child key) could have been derived from a TLS master
        ///     secret (i.e., the parent key) with its metadata.
        /// </summary>
        /// <value>The parent key.</value>
        public ParentKey ParentKey { get; set; }

        /// <summary>
        ///     This element specifies the sensitivity or importance of the key. It could relate to a risk level
        ///     (e.g., Low, Moderate, or High) or a classification level (e.g., Confidential, Secret, or Top Secret)
        /// </summary>
        /// <value>The sensitivity.</value>
        public string Sensitivity { get; set; }

        /// <summary>
        ///     This element specifies the integrity, confidentiality, and source authentication protections applied to
        ///     the key. A public key certificate is an example of key protection whereby the CA’s digital signature
        ///     provides both the integrity protection and source authentication (see [X.509]). A symmetric key and its
        ///     hash value encrypted together is an example of confidentiality and integrity protection. When a key and
        ///     its metadata are received from an external entity, the protections should be verified before the key
        ///     and metadata are operationally used. Generally, a single cryptographic function (e.g., HMAC or digital signature)
        ///     is used to provide both integrity protection and source authentication.
        /// </summary>
        /// <value>The protections.</value>
        public KeyProtection Protection { get; set; }

        /// <summary>
        ///     This element specifies the mechanisms used to provide integrity, confidentiality, and source authentication to the
        ///     associated metadata. Generally, the same mechanism will be used to protect the key and its metadata, especially if
        ///     the key and metadata are transmitted or stored together.
        /// </summary>
        /// <value>The metadata protection.</value>
        public MetadataProtection MetadataProtection { get; set; }

        /// <summary>
        ///     Trusted Association Protections are how the trusted association of metadata to the key is protected. This can be
        ///     part of key protection in other items above. This information is implicitly provided if the key and metadata are
        ///     protected as one aggregated item using the protection listed in items above. Otherwise, the properties contained
        ///     within this property
        ///     should be provided for each trusted association protection.
        /// </summary>
        /// <value>The trusted association protection.</value>
        public TrustedAssociationProtection TrustedAssociationProtection { get; set; }

        /// <summary>
        ///     The important date-times in the lifecycle state transitions of a key.
        /// </summary>
        /// <value>The event epochs.</value>
        public EventEpochs EventEpochs { get; set; }

        /// <summary>
        ///     If a key is revoked, this element specifies the reason for the revocation. Examples include a compromise due to an
        ///     adversary having the key, a compromise due to an adversary having the cryptographic module containing the key, a
        ///     loss of the key, a loss of the cryptographic module containing the key, a suspected key compromise, the key owner
        ///     left the sponsoring organization, and a key misuse by the owner.
        /// </summary>
        /// <value>The revocation reason.</value>
        public string RevocationReason { get; set; }
    }
}