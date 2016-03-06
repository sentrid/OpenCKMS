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
    /// A key may pass through several states between its generation and its destruction.
    /// A key is used differently, depending upon its state in the key’s lifecycle. 
    /// Key states are defined from a system point-of-view, as opposed to the point-of-view of 
    /// a single cryptographic module. The following sections discuss the states that an 
    /// operational or backed-up key may assume, along with transitions to other states. 
    /// Additional states may be applicable for some systems (e.g., a destroyed compromised 
    /// state, which was depicted in the example provided in a previous version of this Recommendation), 
    /// and some of the identified states may not be needed for other systems (e.g., if keys 
    /// are to be activated immediately after generation, the pre-activation state may not be 
    /// needed, or a decision could be made that the suspended state will not be used).
    /// Transitioning between states often requires recording the event. Suitable places for such 
    /// recordings are audit logs and the key's metadata.
    /// </summary>
    public enum KeyLifecycleState
    {
        /// <summary>
        /// The key has been generated, but has not been authorized for use. 
        /// In this state, the key may only be used to perform proof-of-possession 
        /// or key confirmation. Other than for proof-of-possession or 
        /// key-confirmation purposes, a key shall not be used to apply cryptographic 
        /// protection to information (e.g., encrypt or sign information to be 
        /// transmitted or stored) or to process cryptographically protected 
        /// information (e.g., decrypt ciphertext or verify a digital signature) 
        /// while in this state.
        /// </summary>
        PreActivation,

        /// <summary>
        /// The key may be used to cryptographically protect information 
        /// (e.g., encrypt plain text or generate a digital signature), to cryptographically 
        /// process previously protected information (e.g., decrypt ciphertext or verify 
        /// a digital signature) or both. When a key is active, it may be designated for 
        /// protection only, processing only, or both protection and processing, depending 
        /// on its type. For example, private signature keys and public key-transport keys 
        /// are implicitly designated for only applying protection; public signature-verification 
        /// keys and private key-transport keys are designated for processing only. A symmetric 
        /// data-encryption key may be used to encrypt data during its originator-usage period 
        /// and decrypt the encrypted data during its recipient-usage period
        /// </summary>
        Active,

        /// <summary>
        /// <para>The use of a key or key pair may be suspended for several possible reasons; 
        /// in the case of asymmetric key pairs, both the public and private keys shall be suspended 
        /// at the same time. One reason for a suspension might be a possible key compromise, and the 
        /// suspension has been issued to allow time to investigate the situation. Another reason 
        /// might be that the entity that owns a digital signature key pair is not available 
        /// (e.g., is on an extended leave of absence); signatures purportedly signed during the 
        /// suspension time would be invalid.</para>
        /// <para>A suspended key or key pair may be restored to an active state at a later time or may 
        /// be deactivated or destroyed, or may transition to the compromised state.</para>
        /// <para>A suspended key shall not be used to apply cryptographic protection 
        /// (e.g., encrypt plaintext or generate a digital signature). However, a suspended key could be 
        /// used to process information that was protected prior to the suspension (e.g., decrypt 
        /// ciphertext or verify a digital signature), but the recipient must accept the risk in doing 
        /// so (e.g., the recipient must understand the reason and implications of the suspension). 
        /// For example, if the reason for the suspension is because of a suspected compromise, 
        /// it may not be prudent to verify signatures using the public key unless the key pair is 
        /// subsequently reactivated. Information for which protection is known to be applied during 
        /// the suspension period shall not be processed until leaving the suspended state, at which 
        /// time its processing depends on the new state.</para>
        /// </summary>
        Suspended,

        /// <summary>
        /// Keys in the deactivated state shall not be used to apply cryptographic protection, but in some cases, 
        /// may be used to process cryptographically protected information. If the key has been revoked 
        /// (i.e., for reasons other than a compromise), then the key may continue to be used for processing. 
        /// Note that keys retrieved from an archive can be considered to be in the deactivated state unless 
        /// compromised.
        /// </summary>
        Deactivated,

        /// <summary>
        /// <para>Generally, keys are compromised when they are released to or determined by an unauthorized 
        /// entity. A compromised key shall not be used to apply cryptographic protection to information. 
        /// However, in some cases, a compromised key or a public key that corresponds to a compromised private 
        /// key of a key pair may be used to process cryptographically protected information. For example, a 
        /// signature may be verified to determine the integrity of signed data if its signature has been physically 
        /// protected since a time before the compromise occurred. This processing shall be done only under very 
        /// highly controlled conditions, where the users of the information are fully aware of the possible 
        /// consequences.</para>
        /// <para>Note that keys retrieved from an archive may be in the compromised state.</para>
        /// </summary>
        Compromised,

        /// <summary>
        /// <para>The key has been destroyed. Even though the key no longer exists when in this state, 
        /// certain key metadata (e.g., key state transition history, key name, type, and crypto-period)
        ///  may be retained for audit purposes.</para>
        /// <para>It is possible that a compromise of the destroyed key could be determined after the key has been destroyed. 
        /// In this case, the compromise should be recorded.</para>
        /// </summary>
        Destroyed
    }
}