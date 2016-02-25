// ***********************************************************************
// Assembly : 
// Author : NCVEVC
// Created : 02-19-2016
//
// Last Modified By : NCVEVC
// Last Modified On : 02-19-2016
// ***********************************************************************
// <copyright file="Cryptography.h" company="">
// Copyright (c) . All rights reserved.
// </copyright>
// <summary></summary>
// ***********************************************************************
#pragma once
using namespace System;
namespace OpenCKMS {

	using CryptContext = int;
	using CryptUser = int;
	using CryptObject = int;
	using CryptHandle = int;
	using SessionContext = int;
	using CryptCertificate = int;
	using CryptKeyset = int;
	using CryptEnvelope = int;
	using CryptDevice = int;

#pragma region Data Structures

	public value class AlgorithmCapabilities {
	public:
		String^ AlgorithmName;
		int BlockSize;
		int MinKeySize;
		int KeySize;
		int MaxKeySize;
};

	public value class ObjectInformation {
	public:
		int Type;
		int Algorithm;
		int Mode;
		int HashAlgorithm;
		array<System::Byte>^ Salt;
		int SaltSize;
	};

	public value class QueryInfo {
	public:
		String^ AlgorithmName;
		int BlockSize;
		int MinimumKeySize;
		int KeySize;
		int MaximumKeySize;
	};

	public value class RsaInfo {
	public:
		bool IsPublicKey;
		array<Char>^ Modulus;

	};

	public value class CertificateExtension {
	public:
		bool IsCritical;
		String^ Oid;
		int Length;
	};

	public ref class ExtendedErrorInformation {
	public:
		int ErrorCode;
		int ErrorType;
		int ErrorLocus;
		String^ ErrorDescription;
	};

#pragma endregion

#pragma region Enumerations

	public enum class Algorithm {
		None = 0, // No encryption
		Des = 1, // DES
		TripleDes = 2, // Triple DES
		Idea = 3, // IDEA (only used for PGP 2.x)
		Cast = 4, // CAST-128 (only used for OpenPGP)
		Rc2 = 5, // RC2 (disabled by default, used for PKCS #12)
		Rc4 = 6, // RC4 (insecure, deprecated)
		Reserved1 = 7, // Formerly RC5
		Aes = 8, // AES
		Reserved2 = 9, // Formerly Blowfish
		Dh = 100, // Diffie-Hellman
		Rsa = 101, // RSA
		Dsa = 102, // DSA
		Elgamal = 103, // ElGamal
		Reserved3 = 104, // Formerly KEA
		Ecdsa = 105, // ECDSA
		Ecdh = 106, // ECDH
		Reserved4 = 200, // Formerly MD2
		Reserved5 = 201, // Formerly MD4
		Md5 = 202, // MD5 (only used for TLS 1.0/1.1)
		Sha1 = 203, // SHA/SHA1
		Reserved6 = 204, // Formerly RIPE-MD 160
		Sha2 = 205, // SHA-256
		Sha256 = 205, // Alternate name
		ShaNg = 206, // Future SHA-nextgen standard
		Resreved7 = 300, // Formerly HMAC-MD5
		HmacSha1 = 301, // HMAC-SHA
		Reserved8 = 302, // Formerly HMAC-RIPEMD-160
		HmacSha2 = 303, // HMAC-SHA2
		HmacShang = 304, // HMAC-future-SHA-nextgen
		Last = 305, // Last possible crypt value
		FirstConventional = 1,
		LastConventional = 99,
		FirstPkc = 100,
		LastPkc = 199,
		FirstHash = 200,
		LastHash = 299,
		FirstMac = 300,
		LastMac = 399
	};

	public enum class CryptographicMode {
		Ecb = 1, // ECB 
		Cbc = 2, // CBC 
		Cfb = 3, // CFB 
		Gcm = 4, // GCM 
		Last = 5 // Last possible crypt mode value
	};

	public enum class KeysetType {
		None = 0, // No keyset type 
		File = 1, // Generic flat file keyset 
		Http = 2, // Web page containing cert/CRL
		Ldap = 3, // LDAP directory service 
		Odbc = 4, // Generic ODBC interface 
		Database = 5, // Generic RDBMS interface 
		OdbcStore = 6, // ODBC certificate store 
		DatabaseStore = 7, // Database certificate store 
		Last = 8 // Last possible keyset type 
	};

	public enum class DeviceType {
		Fortezza = 1, // Fortezza card - Placeholder only
		Pkcs11 = 2, // PKCS #11 crypto token 
		Cryptoapi = 3, // Microsoft CryptoAPI 
		Hardware = 4, // Generic crypo HW plugin 
		Last = 5 // Last possible crypto device type
	};

	public enum class CertificateType {
		None = 0, // No certificate type 
		Certificate = 1, // Certificate 
		AttributeCert = 2, // Attribute certificate 
		Certchain = 3, // PKCS #7 certificate chain 
		Certrequest = 4, // PKCS #10 certification request
		RequestCert = 5, // CRMF certification request 
		RequestRevocation = 6, // CRMF revocation request 
		Crl = 7, // CRL 
		CmsAttributes = 8, // CMS attributes 
		RtcsRequest = 9, // RTCS request 
		RtcsResponse = 10, // RTCS response 
		OcspRequest = 11, // OCSP request 
		OcspResponse = 12, // OCSP response 
		Pkiuser = 13, // PKI user information 
		Last = 14 // Last possible cert.type 
	};

	public enum class Format {
		None = 0, // No format type 
		Auto = 1, // Deenv, auto-determine type 
		Cryptlib = 2, // cryptlib native format 
		Cms = 3, // PKCS #7 / CMS / S/MIME fmt. 
		Pkcs7 = 3,
		Smime = 4, // As CMS with MSG-style behaviour
		Pgp = 5, // PGP format 
		Last = 6 // Last possible format type 
	};

	public enum class SessionType {
		None = 0, // No session type 
		Ssh = 1, // SSH 
		SshServer = 2, // SSH server 
		Ssl = 3, // SSL/TLS 
		Tls = 3,
		SslServer = 4, // SSL/TLS server 
		TlsServer = 4,
		Rtcs = 5, // RTCS 
		RtcsServer = 6, // RTCS server 
		Ocsp = 7, // OCSP 
		OcspServer = 8, // OCSP server 
		Tsp = 9, // TSP 
		TspServer = 10, // TSP server 
		Cmp = 11, // CMP 
		CmpServer = 12, // CMP server 
		Scep = 13, // SCEP 
		ScepServer = 14, // SCEP server 
		CertstoreServer = 15, // HTTP cert store interface 
		Last = 16 // Last possible session type
	};

	public enum class UserType {
		Normal = 1, // Normal user 
		So = 2, // Security officer 
		Ca = 3, // CA user 
		Last = 4 // Last possible user type
	};

	public enum class AttributeType {
		AttributeNone = 0, // Non-value
		PropertyFirst = 1, // *******************
		PropertyHighsecurity = 2, // Owned+non-forwardcount+locked
		PropertyOwner = 3, // Object owner
		PropertyForwardcount = 4, // No.of times object can be forwarded
		PropertyLocked = 5, // Whether properties can be chged/read
		PropertyUsagecount = 6, // Usage count before object expires
		PropertyNonexportable = 7, // Whether key is nonexp.from context
		PropertyLast = 8,
		GenericFirst = 9, // Extended error information
		AttributeErrortype = 10, // Type of last error
		AttributeErrorlocus = 11, // Locus of last error
		AttributeErrormessage = 12, // Detailed error description
		AttributeCurrentGroup = 13, // Cursor mgt: Group in attribute list
		AttributeCurrent = 14, // Cursor mgt: Entry in attribute list
		AttributeCurrentInstance = 15, // Cursor mgt: Instance in attribute list
		AttributeBuffersize = 16, // Internal data buffer size
		GenericLast = 17,
		OptionFirst = 100, // **************************
		OptionInfoDescription = 101, // Text description
		OptionInfoCopyright = 102, // Copyright notice
		OptionInfoMajorversion = 103, // Major release version
		OptionInfoMinorversion = 104, // Minor release version
		OptionInfoStepping = 105, // Release stepping
		OptionEncrAlgo = 106, // Encryption algorithm
		OptionEncrHash = 107, // Hash algorithm
		OptionEncrMac = 108, // MAC algorithm
		OptionPkcAlgo = 109, // Public-key encryption algorithm
		OptionPkcKeysize = 110, // Public-key encryption key size
		OptionSigAlgo = 111, // Signature algorithm
		OptionSigKeysize = 112, // Signature keysize
		OptionKeyingAlgo = 113, // Key processing algorithm
		OptionKeyingIterations = 114, // Key processing iterations
		OptionCertSignunrecognisedattribUTES = 115, // Whether to sign unrecog.attrs
		OptionCertValidity = 116, // Certificate validity period
		OptionCertUpdateinterval = 117, // CRL update interval
		OptionCertComplianceLevel = 118, // PKIX compliance level for cert chks.
		OptionCertRequirepolicy = 119, // Whether explicit policy req'd for certs
		OptionCmsDefaultattributes = 120, // Add default CMS attributes
		OptionSmimeDefaultattributes = 120, // LDAP keyset options
		OptionKeysLdapObjectclass = 121, // Object class
		OptionKeysLdapObjecttype = 122, // Object type to fetch
		OptionKeysLdapFilter = 123, // Query filter
		OptionKeysLdapCacertname = 124, // CA certificate attribute name
		OptionKeysLdapCertname = 125, // Certificate attribute name
		OptionKeysLdapCrlname = 126, // CRL attribute name
		OptionKeysLdapEmailname = 127, // Email attribute name
		OptionDevicePkcs11Dvr01 = 128, // Name of first PKCS #11 driver
		OptionDevicePkcs11Dvr02 = 129, // Name of second PKCS #11 driver
		OptionDevicePkcs11Dvr03 = 130, // Name of third PKCS #11 driver
		OptionDevicePkcs11Dvr04 = 131, // Name of fourth PKCS #11 driver
		OptionDevicePkcs11Dvr05 = 132, // Name of fifth PKCS #11 driver
		OptionDevicePkcs11Hardwareonly = 133, // Use only hardware mechanisms
		OptionNetSocksServer = 134, // Socks server name
		OptionNetSocksUsername = 135, // Socks user name
		OptionNetHttpProxy = 136, // Web proxy server
		OptionNetConnecttimeout = 137, // Timeout for network connection setup
		OptionNetReadtimeout = 138, // Timeout for network reads
		OptionNetWritetimeout = 139, // Timeout for network writes
		OptionMiscAsyncinit = 140, // Whether to init cryptlib async'ly
		OptionMiscSidechannelprotection = 141, // Protect against side-channel attacks
		OptionConfigchanged = 142, // Whether in-mem.opts match on-disk ones
		OptionSelftestok = 143, // Whether self-test was completed and OK
		OptionLast = 144,
		CtxInfoFirst = 1000, // ********************
		CtxInfoAlgo = 1001, // Algorithm
		CtxInfoMode = 1002, // Mode
		CtxInfoNameAlgo = 1003, // Algorithm name
		CtxInfoNameMode = 1004, // Mode name
		CtxInfoKeysize = 1005, // Key size in bytes
		CtxInfoBlocksize = 1006, // Block size
		CtxInfoIvSize = 1007, // IV size
		CtxInfoKeyingAlgo = 1008, // Key processing algorithm
		CtxInfoKeyingIterations = 1009, // Key processing iterations
		CtxInfoKeyingSalt = 1010, // Key processing salt
		CtxInfoKeyingValue = 1011, // Value used to derive key
		CtxInfoKey = 1012, // Key
		CtxInfoKeyComponents = 1013, // Public-key components
		CtxInfoIv = 1014, // IV
		CtxInfoHashvalue = 1015, // Hash value
		CtxInfoLabel = 1016, // Label for private/secret key
		CtxInfoPersistent = 1017, // Obj.is backed by device or keyset
		CtxInfoLast = 1018,
		CertificateInfoFirst = 2000, // ************************
		CertificateInfoSelfsigned = 2001, // Cert is self-signed
		CertificateInfoImmutable = 2002, // Cert is signed and immutable
		CertificateInfoXyzzy = 2003, // Cert is a magic just-works cert
		CertificateInfoCerttype = 2004, // Certificate object type
		CertificateInfoFingerprintSha1 = 2005, // Certificate fingerprints
		CertificateInfoFingerprintSha2 = 2006,
		CertificateInfoFingerprintShang = 2007,
		CertificateInfoCurrentCertificate = 2008, // Cursor mgt: Rel.pos in chain/CRL/OCSP
		CertificateInfoTrustedUsage = 2009, // Usage that cert is trusted for
		CertificateInfoTrustedImplicit = 2010, // Whether cert is implicitly trusted
		CertificateInfoSignaturelevel = 2011, // Amount of detail to include in sigs.
		CertificateInfoVersion = 2012, // Cert.format version
		CertificateInfoSerialnumber = 2013, // Serial number
		CertificateInfoSubjectpublicKeyInfo = 2014, // Public key
		CertificateInfoCertificate = 2015, // User certificate
		CertificateInfoUsercertificate = 2015,
		CertificateInfoCacertificate = 2016, // CA certificate
		CertificateInfoIssuername = 2017, // Issuer DN
		CertificateInfoValidfrom = 2018, // Cert valid-from time
		CertificateInfoValidto = 2019, // Cert valid-to time
		CertificateInfoSubjectname = 2020, // Subject DN
		CertificateInfoIssueruniqueid = 2021, // Issuer unique ID
		CertificateInfoSubjectuniqueid = 2022, // Subject unique ID
		CertificateInfoCertrequest = 2023, // Cert.request (DN + public key)
		CertificateInfoThisupdate = 2024, // CRL/OCSP current-update time
		CertificateInfoNextupdate = 2025, // CRL/OCSP next-update time
		CertificateInfoRevocationdate = 2026, // CRL/OCSP cert-revocation time
		CertificateInfoRevocationstatus = 2027, // OCSP revocation status
		CertificateInfoCertstatus = 2028, // RTCS certificate status
		CertificateInfoDn = 2029, // Currently selected DN in string form
		CertificateInfoPkiuserId = 2030, // PKI user ID
		CertificateInfoPkiuserIssuepassword = 2031, // PKI user issue password
		CertificateInfoPkiuserRevpassword = 2032, // PKI user revocation password
		CertificateInfoPkiuserRa = 2033, // PKI user is an RA
		CertificateInfoCountryname = 2100, // countryName
		CertificateInfoStateorprovincename = 2101, // stateOrProvinceName
		CertificateInfoLocalityname = 2102, // localityName
		CertificateInfoOrganizationname = 2103, // organizationName
		CertificateInfoOrganisationname = 2103,
		CertificateInfoOrganizationalunitname = 2104, // organizationalUnitName
		CertificateInfoOrganisationalunitname = 2104,
		CertificateInfoCommonname = 2105, // commonName
		CertificateInfoOthernameTypeid = 2106, // otherName.typeID
		CertificateInfoOthernameValue = 2107, // otherName.value
		CertificateInfoRfc822Name = 2108, // rfc822Name
		CertificateInfoEmail = 2108,
		CertificateInfoDnsname = 2109, // dNSName
		CertificateInfoDirectoryname = 2110, // directoryName
		CertificateInfoEdipartynameNameassigner = 2111, // ediPartyName.nameAssigner
		CertificateInfoEdipartynamePartyname = 2112, // ediPartyName.partyName
		CertificateInfoUniformresourceidentifier = 2113, // uniformResourceIdentifier
		CertificateInfoUrl = 2113,
		CertificateInfoIpaddress = 2114, // iPAddress
		CertificateInfoRegisteredid = 2115, // registeredID
		CertificateInfoChallengepassword = 2200, // 1 3 6 1 4 1 3029 3 1 4 cRLExtReason
		CertificateInfoCrlextreason = 2201, // 1 3 6 1 4 1 3029 3 1 5 keyFeatures
		CertificateInfoKeyfeatures = 2202, // 1 3 6 1 5 5 7 1 1 authorityInfoAccess
		CertificateInfoAuthorityinfoaccess = 2203,
		CertificateInfoAuthorityinfoRtcs = 2204, // accessDescription.accessLocation
		CertificateInfoAuthorityinfoOcsp = 2205, // accessDescription.accessLocation
		CertificateInfoAuthorityinfoCaissuers = 2206, // accessDescription.accessLocation
		CertificateInfoAuthorityinfoCertstore = 2207, // accessDescription.accessLocation
		CertificateInfoAuthorityinfoCrls = 2208, // accessDescription.accessLocation
		CertificateInfoBiometricinfo = 2209,
		CertificateInfoBiometricinfoType = 2210, // biometricData.typeOfData
		CertificateInfoBiometricinfoHashalgo = 2211, // biometricData.hashAlgorithm
		CertificateInfoBiometricinfoHash = 2212, // biometricData.dataHash
		CertificateInfoBiometricinfoUrl = 2213, // biometricData.sourceDataUri
		CertificateInfoQcstatement = 2214,
		CertificateInfoQcstatementSemantics = 2215, // qcStatement.statementInfo.semanticsIdentifier
		CertificateInfoQcstatementRegistrationaUTHORITY = 2216, // qcStatement.statementInfo.nameRegistrationAuthorities
		CertificateInfoIpaddressblocks = 2217,
		CertificateInfoIpaddressblocksAddressfaMILY = 2218, // addressFamily */	CRYPTCertificateInfoIPADDRESSBLOCKSPREFIX,	/* ipAddress.addressPrefix
		CertificateInfoIpaddressblocksPrefix = 2219, // ipAddress.addressPrefix
		CertificateInfoIpaddressblocksMin = 2220, // ipAddress.addressRangeMin
		CertificateInfoIpaddressblocksMax = 2221, // ipAddress.addressRangeMax
		CertificateInfoAutonomoussysids = 2222,
		CertificateInfoAutonomoussysidsAsnumId = 2223, // asNum.id
		CertificateInfoAutonomoussysidsAsnumMiN = 2224, // asNum.min
		CertificateInfoAutonomoussysidsAsnumMaX = 2225, // asNum.max
		CertificateInfoOcspNonce = 2226, // nonce
		CertificateInfoOcspResponse = 2227,
		CertificateInfoOcspResponseOcsp = 2228, // OCSP standard response
		CertificateInfoOcspNocheck = 2229, // 1 3 6 1 5 5 7 48 1 6 ocspArchiveCutoff
		CertificateInfoOcspArchivecutoff = 2230, // 1 3 6 1 5 5 7 48 1 11 subjectInfoAccess
		CertificateInfoSubjectinfoaccess = 2231,
		CertificateInfoSubjectinfoTimestamping = 2232, // accessDescription.accessLocation
		CertificateInfoSubjectinfoCarepository = 2233, // accessDescription.accessLocation
		CertificateInfoSubjectinfoSignedobjectrEPOSITORY = 2234, // accessDescription.accessLocation
		CertificateInfoSubjectinfoRpkimanifest = 2235, // accessDescription.accessLocation
		CertificateInfoSubjectinfoSignedobject = 2236, // accessDescription.accessLocation
		CertificateInfoSiggDateofcertgen = 2237, // 1 3 36 8 3 2 siggProcuration
		CertificateInfoSiggProcuration = 2238,
		CertificateInfoSiggProcureCountry = 2239, // country
		CertificateInfoSiggProcureTypeofsubstiTUTION = 2240, // typeOfSubstitution
		CertificateInfoSiggProcureSigningfor = 2241, // signingFor.thirdPerson
		CertificateInfoSiggAdmissions = 2242,
		CertificateInfoSiggAdmissionsAuthority = 2243, // authority
		CertificateInfoSiggAdmissionsNamingautHID = 2244, // namingAuth.iD
		CertificateInfoSiggAdmissionsNamingautHURL = 2245, // namingAuth.uRL
		CertificateInfoSiggAdmissionsNamingautHTEXT = 2246, // namingAuth.text
		CertificateInfoSiggAdmissionsProfessioNITEM = 2247, // professionItem
		CertificateInfoSiggAdmissionsProfessioNOID = 2248, // professionOID
		CertificateInfoSiggAdmissionsRegistratIONNUMBER = 2249, // registrationNumber
		CertificateInfoSiggMonetarylimit = 2250,
		CertificateInfoSiggMonetaryCurrency = 2251, // currency
		CertificateInfoSiggMonetaryAmount = 2252, // amount
		CertificateInfoSiggMonetaryExponent = 2253, // exponent
		CertificateInfoSiggDeclarationofmajoritY = 2254,
		CertificateInfoSiggDeclarationofmajoritYCOUNTRY = 2255, // fullAgeAtCountry
		CertificateInfoSiggRestriction = 2256, // 1 3 36 8 3 13 siggCertHash
		CertificateInfoSiggCerthash = 2257, // 1 3 36 8 3 15 siggAdditionalInformation
		CertificateInfoSiggAdditionalinformatioN = 2258, // 1 3 101 1 4 1 strongExtranet
		CertificateInfoStrongextranet = 2259,
		CertificateInfoStrongextranetZone = 2260, // sxNetIDList.sxNetID.zone
		CertificateInfoStrongextranetId = 2261, // sxNetIDList.sxNetID.id
		CertificateInfoSubjectdirectoryattributeS = 2262,
		CertificateInfoSubjectdirType = 2263, // attribute.type
		CertificateInfoSubjectdirValues = 2264, // attribute.values
		CertificateInfoSubjectkeyidentifier = 2265, // 2 5 29 15 keyUsage
		CertificateInfoKeyusage = 2266, // 2 5 29 16 privateKeyUsagePeriod
		CertificateInfoPrivatekeyusageperiod = 2267,
		CertificateInfoPrivatekeyNotbefore = 2268, // notBefore
		CertificateInfoPrivatekeyNotafter = 2269, // notAfter
		CertificateInfoSubjectaltname = 2270, // 2 5 29 18 issuerAltName
		CertificateInfoIssueraltname = 2271, // 2 5 29 19 basicConstraints
		CertificateInfoBasicconstraints = 2272,
		CertificateInfoCa = 2273, // cA
		CertificateInfoAuthority = 2273,
		CertificateInfoPathlenconstraint = 2274, // pathLenConstraint
		CertificateInfoCrlnumber = 2275, // 2 5 29 21 cRLReason
		CertificateInfoCrlreason = 2276, // 2 5 29 23 holdInstructionCode
		CertificateInfoHoldinstructioncode = 2277, // 2 5 29 24 invalidityDate
		CertificateInfoInvaliditydate = 2278, // 2 5 29 27 deltaCRLIndicator
		CertificateInfoDeltacrlindicator = 2279, // 2 5 29 28 issuingDistributionPoint
		CertificateInfoIssuingdistributionpoint = 2280,
		CertificateInfoIssuingdistFullname = 2281, // distributionPointName.fullName
		CertificateInfoIssuingdistUsercertsonly = 2282, // onlyContainsUserCerts
		CertificateInfoIssuingdistCacertsonly = 2283, // onlyContainsCACerts
		CertificateInfoIssuingdistSomereasonsonLY = 2284, // onlySomeReasons
		CertificateInfoIssuingdistIndirectcrl = 2285, // indirectCRL
		CertificateInfoCertificateissuer = 2286, // 2 5 29 30 nameConstraints
		CertificateInfoNameconstraints = 2287,
		CertificateInfoPermittedsubtrees = 2288, // permittedSubtrees
		CertificateInfoExcludedsubtrees = 2289, // excludedSubtrees
		CertificateInfoCrldistributionpoint = 2290,
		CertificateInfoCrldistFullname = 2291, // distributionPointName.fullName
		CertificateInfoCrldistReasons = 2292, // reasons
		CertificateInfoCrldistCrlissuer = 2293, // cRLIssuer
		CertificateInfoCertificatepolicies = 2294,
		CertificateInfoCertpolicyid = 2295, // policyInformation.policyIdentifier
		CertificateInfoCertpolicyCpsuri = 2296, // policyInformation.policyQualifiers.qualifier.cPSuri
		CertificateInfoCertpolicyOrganization = 2297, // policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.organization
		CertificateInfoCertpolicyNoticenumbers = 2298, // policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.noticeNumbers
		CertificateInfoCertpolicyExplicittext = 2299, // policyInformation.policyQualifiers.qualifier.userNotice.explicitText
		CertificateInfoPolicymappings = 2300,
		CertificateInfoIssuerdomainpolicy = 2301, // policyMappings.issuerDomainPolicy
		CertificateInfoSubjectdomainpolicy = 2302, // policyMappings.subjectDomainPolicy
		CertificateInfoAuthoritykeyidentifier = 2303,
		CertificateInfoAuthorityKeyidentifier = 2304, // keyIdentifier
		CertificateInfoAuthorityCertissuer = 2305, // authorityCertIssuer
		CertificateInfoAuthorityCertserialnumbeR = 2306, // authorityCertSerialNumber
		CertificateInfoPolicyconstraints = 2307,
		CertificateInfoRequireexplicitpolicy = 2308, // policyConstraints.requireExplicitPolicy
		CertificateInfoInhibitpolicymapping = 2309, // policyConstraints.inhibitPolicyMapping
		CertificateInfoExtkeyusage = 2310,
		CertificateInfoExtkeyMsIndividualcodesIGNING = 2311, // individualCodeSigning
		CertificateInfoExtkeyMsCommercialcodesIGNING = 2312, // commercialCodeSigning
		CertificateInfoExtkeyMsCerttrustlistsiGNING = 2313, // certTrustListSigning
		CertificateInfoExtkeyMsTimestampsigninG = 2314, // timeStampSigning
		CertificateInfoExtkeyMsServergatedcrypTO = 2315, // serverGatedCrypto
		CertificateInfoExtkeyMsEncryptedfilesySTEM = 2316, // encrypedFileSystem
		CertificateInfoExtkeyServerauth = 2317, // serverAuth
		CertificateInfoExtkeyClientauth = 2318, // clientAuth
		CertificateInfoExtkeyCodesigning = 2319, // codeSigning
		CertificateInfoExtkeyEmailprotection = 2320, // emailProtection
		CertificateInfoExtkeyIpsecendsystem = 2321, // ipsecEndSystem
		CertificateInfoExtkeyIpsectunnel = 2322, // ipsecTunnel
		CertificateInfoExtkeyIpsecuser = 2323, // ipsecUser
		CertificateInfoExtkeyTimestamping = 2324, // timeStamping
		CertificateInfoExtkeyOcspsigning = 2325, // ocspSigning
		CertificateInfoExtkeyDirectoryservice = 2326, // directoryService
		CertificateInfoExtkeyAnykeyusage = 2327, // anyExtendedKeyUsage
		CertificateInfoExtkeyNsServergatedcrypTO = 2328, // serverGatedCrypto
		CertificateInfoExtkeyVsServergatedcrypTOCA = 2329, // serverGatedCrypto CA
		CertificateInfoCrlstreamidentifier = 2330, // 2 5 29 46 freshestCRL
		CertificateInfoFreshestcrl = 2331,
		CertificateInfoFreshestcrlFullname = 2332, // distributionPointName.fullName
		CertificateInfoFreshestcrlReasons = 2333, // reasons
		CertificateInfoFreshestcrlCrlissuer = 2334, // cRLIssuer
		CertificateInfoOrderedlist = 2335, // 2 5 29 51 baseUpdateTime
		CertificateInfoBaseupdatetime = 2336, // 2 5 29 53 deltaInfo
		CertificateInfoDeltainfo = 2337,
		CertificateInfoDeltainfoLocation = 2338, // deltaLocation
		CertificateInfoDeltainfoNextdelta = 2339, // nextDelta
		CertificateInfoInhibitanypolicy = 2340, // 2 5 29 58 toBeRevoked
		CertificateInfoToberevoked = 2341,
		CertificateInfoToberevokedCertissuer = 2342, // certificateIssuer
		CertificateInfoToberevokedReasoncode = 2343, // reasonCode
		CertificateInfoToberevokedRevocationtimE = 2344, // revocationTime
		CertificateInfoToberevokedCertserialnumBER = 2345, // certSerialNumber
		CertificateInfoRevokedgroups = 2346,
		CertificateInfoRevokedgroupsCertissuer = 2347, // certificateIssuer
		CertificateInfoRevokedgroupsReasoncode = 2348, // reasonCode
		CertificateInfoRevokedgroupsInvaliditydATE = 2349, // invalidityDate
		CertificateInfoRevokedgroupsStartingnumBER = 2350, // startingNumber
		CertificateInfoRevokedgroupsEndingnumbeR = 2351, // endingNumber
		CertificateInfoExpiredcertsoncrl = 2352, // 2 5 29 63 aaIssuingDistributionPoint
		CertificateInfoAaissuingdistributionpoinT = 2353,
		CertificateInfoAaissuingdistFullname = 2354, // distributionPointName.fullName
		CertificateInfoAaissuingdistSomereasonsONLY = 2355, // onlySomeReasons
		CertificateInfoAaissuingdistIndirectcrl = 2356, // indirectCRL
		CertificateInfoAaissuingdistUserattrcerTS = 2357, // containsUserAttributeCerts
		CertificateInfoAaissuingdistAacerts = 2358, // containsAACerts
		CertificateInfoAaissuingdistSoacerts = 2359, // containsSOAPublicKeyCerts
		CertificateInfoNsCerttype = 2360, // netscape-cert-type
		CertificateInfoNsBaseurl = 2361, // netscape-base-url
		CertificateInfoNsRevocationurl = 2362, // netscape-revocation-url
		CertificateInfoNsCarevocationurl = 2363, // netscape-ca-revocation-url
		CertificateInfoNsCertrenewalurl = 2364, // netscape-cert-renewal-url
		CertificateInfoNsCapolicyurl = 2365, // netscape-ca-policy-url
		CertificateInfoNsSslservername = 2366, // netscape-ssl-server-name
		CertificateInfoNsComment = 2367, // netscape-comment
		CertificateInfoSetHashedrootkey = 2368,
		CertificateInfoSetRootkeythumbprint = 2369, // rootKeyThumbPrint
		CertificateInfoSetCertificatetype = 2370, // 2 23 42 7 2 SET merchantData
		CertificateInfoSetMerchantdata = 2371,
		CertificateInfoSetMerid = 2372, // merID
		CertificateInfoSetMeracquirerbin = 2373, // merAcquirerBIN
		CertificateInfoSetMerchantlanguage = 2374, // merNames.language
		CertificateInfoSetMerchantname = 2375, // merNames.name
		CertificateInfoSetMerchantcity = 2376, // merNames.city
		CertificateInfoSetMerchantstateprovince = 2377, // merNames.stateProvince
		CertificateInfoSetMerchantpostalcode = 2378, // merNames.postalCode
		CertificateInfoSetMerchantcountryname = 2379, // merNames.countryName
		CertificateInfoSetMercountry = 2380, // merCountry
		CertificateInfoSetMerauthflag = 2381, // merAuthFlag
		CertificateInfoSetCertcardrequired = 2382, // 2 23 42 7 4 SET tunneling
		CertificateInfoSetTunneling = 2383,
		CertificateInfoSetTunnelling = 2383,
		CertificateInfoSetTunnelingflag = 2384, // tunneling
		CertificateInfoSetTunnellingflag = 2384,
		CertificateInfoSetTunnelingalgid = 2385, // tunnelingAlgID
		CertificateInfoSetTunnellingalgid = 2385, // S/MIME attributes
		CertificateInfoCmsContenttype = 2500, // 1 2 840 113549 1 9 4 messageDigest
		CertificateInfoCmsMessagedigest = 2501, // 1 2 840 113549 1 9 5 signingTime
		CertificateInfoCmsSigningtime = 2502, // 1 2 840 113549 1 9 6 counterSignature
		CertificateInfoCmsCountersignature = 2503, // counterSignature
		CertificateInfoCmsSigningdescription = 2504, // 1 2 840 113549 1 9 15 sMIMECapabilities
		CertificateInfoCmsSmimecapabilities = 2505,
		CertificateInfoCmsSmimecap3Des = 2506, // 3DES encryption
		CertificateInfoCmsSmimecapAes = 2507, // AES encryption
		CertificateInfoCmsSmimecapCast128 = 2508, // CAST-128 encryption
		CertificateInfoCmsSmimecapShang = 2509, // SHA2-ng hash
		CertificateInfoCmsSmimecapSha2 = 2510, // SHA2-256 hash
		CertificateInfoCmsSmimecapSha1 = 2511, // SHA1 hash
		CertificateInfoCmsSmimecapHmacShang = 2512, // HMAC-SHA2-ng MAC
		CertificateInfoCmsSmimecapHmacSha2 = 2513, // HMAC-SHA2-256 MAC
		CertificateInfoCmsSmimecapHmacSha1 = 2514, // HMAC-SHA1 MAC
		CertificateInfoCmsSmimecapAuthenc256 = 2515, // AuthEnc w.256-bit key
		CertificateInfoCmsSmimecapAuthenc128 = 2516, // AuthEnc w.128-bit key
		CertificateInfoCmsSmimecapRsaShang = 2517, // RSA with SHA-ng signing
		CertificateInfoCmsSmimecapRsaSha2 = 2518, // RSA with SHA2-256 signing
		CertificateInfoCmsSmimecapRsaSha1 = 2519, // RSA with SHA1 signing
		CertificateInfoCmsSmimecapDsaSha1 = 2520, // DSA with SHA-1 signing
		CertificateInfoCmsSmimecapEcdsaShang = 2521, // ECDSA with SHA-ng signing
		CertificateInfoCmsSmimecapEcdsaSha2 = 2522, // ECDSA with SHA2-256 signing
		CertificateInfoCmsSmimecapEcdsaSha1 = 2523, // ECDSA with SHA-1 signing
		CertificateInfoCmsSmimecapPrefersignedDATA = 2524, // preferSignedData
		CertificateInfoCmsSmimecapCannotdecrypTANY = 2525, // canNotDecryptAny
		CertificateInfoCmsSmimecapPreferbinaryINSIDE = 2526, // preferBinaryInside
		CertificateInfoCmsReceiptrequest = 2527,
		CertificateInfoCmsReceiptContentidentiFIER = 2528, // contentIdentifier
		CertificateInfoCmsReceiptFrom = 2529, // receiptsFrom
		CertificateInfoCmsReceiptTo = 2530, // receiptsTo
		CertificateInfoCmsSecuritylabel = 2531,
		CertificateInfoCmsSeclabelPolicy = 2532, // securityPolicyIdentifier
		CertificateInfoCmsSeclabelClassificatiON = 2533, // securityClassification
		CertificateInfoCmsSeclabelPrivacymark = 2534, // privacyMark
		CertificateInfoCmsSeclabelCattype = 2535, // securityCategories.securityCategory.type
		CertificateInfoCmsSeclabelCatvalue = 2536, // securityCategories.securityCategory.value
		CertificateInfoCmsMlexpansionhistory = 2537,
		CertificateInfoCmsMlexpEntityidentifieR = 2538, // mlData.mailListIdentifier.issuerAndSerialNumber
		CertificateInfoCmsMlexpTime = 2539, // mlData.expansionTime
		CertificateInfoCmsMlexpNone = 2540, // mlData.mlReceiptPolicy.none
		CertificateInfoCmsMlexpInsteadof = 2541, // mlData.mlReceiptPolicy.insteadOf.generalNames.generalName
		CertificateInfoCmsMlexpInadditionto = 2542, // mlData.mlReceiptPolicy.inAdditionTo.generalNames.generalName
		CertificateInfoCmsContenthints = 2543,
		CertificateInfoCmsContenthintDescriptiON = 2544, // contentDescription
		CertificateInfoCmsContenthintType = 2545, // contentType
		CertificateInfoCmsEquivalentlabel = 2546,
		CertificateInfoCmsEqvlabelPolicy = 2547, // securityPolicyIdentifier
		CertificateInfoCmsEqvlabelClassificatiON = 2548, // securityClassification
		CertificateInfoCmsEqvlabelPrivacymark = 2549, // privacyMark
		CertificateInfoCmsEqvlabelCattype = 2550, // securityCategories.securityCategory.type
		CertificateInfoCmsEqvlabelCatvalue = 2551, // securityCategories.securityCategory.value
		CertificateInfoCmsSigningcertificate = 2552,
		CertificateInfoCmsSigningcertEsscertid = 2553, // certs.essCertID
		CertificateInfoCmsSigningcertPolicies = 2554, // policies.policyInformation.policyIdentifier
		CertificateInfoCmsSigningcertificatev2 = 2555,
		CertificateInfoCmsSigningcertv2EsscertIDV2 = 2556, // certs.essCertID
		CertificateInfoCmsSigningcertv2PolicieS = 2557, // policies.policyInformation.policyIdentifier
		CertificateInfoCmsSignaturepolicyid = 2558,
		CertificateInfoCmsSigpolicyid = 2559, // sigPolicyID
		CertificateInfoCmsSigpolicyhash = 2560, // sigPolicyHash
		CertificateInfoCmsSigpolicyCpsuri = 2561, // sigPolicyQualifiers.sigPolicyQualifier.cPSuri
		CertificateInfoCmsSigpolicyOrganizatioN = 2562, // sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.organization
		CertificateInfoCmsSigpolicyNoticenumbeRS = 2563, // sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.noticeNumbers
		CertificateInfoCmsSigpolicyExplicittexT = 2564, // sigPolicyQualifiers.sigPolicyQualifier.userNotice.explicitText
		CertificateInfoCmsSigtypeidentifier = 2565,
		CertificateInfoCmsSigtypeidOriginatorsIG = 2566, // originatorSig
		CertificateInfoCmsSigtypeidDomainsig = 2567, // domainSig
		CertificateInfoCmsSigtypeidAdditionalaTTRIBUTES = 2568, // additionalAttributesSig
		CertificateInfoCmsSigtypeidReviewsig = 2569, // reviewSig
		CertificateInfoCmsNonce = 2570, // randomNonce
		CertificateInfoScepMessagetype = 2571, // messageType
		CertificateInfoScepPkistatus = 2572, // pkiStatus
		CertificateInfoScepFailinfo = 2573, // failInfo
		CertificateInfoScepSendernonce = 2574, // senderNonce
		CertificateInfoScepRecipientnonce = 2575, // recipientNonce
		CertificateInfoScepTransactionid = 2576, // transID
		CertificateInfoCmsSpcagencyinfo = 2577,
		CertificateInfoCmsSpcagencyurl = 2578, // spcAgencyInfo.url
		CertificateInfoCmsSpcstatementtype = 2579,
		CertificateInfoCmsSpcstmtIndividualcodESIGNING = 2580, // individualCodeSigning
		CertificateInfoCmsSpcstmtCommercialcodESIGNING = 2581, // commercialCodeSigning
		CertificateInfoCmsSpcopusinfo = 2582,
		CertificateInfoCmsSpcopusinfoName = 2583, // spcOpusInfo.name
		CertificateInfoCmsSpcopusinfoUrl = 2584, // spcOpusInfo.url
		CertificateInfoLast = 2585,
		KeyInfoFirst = 3000, // *******************
		KeyInfoQuery = 3001, // Keyset query
		KeyInfoQueryRequests = 3002, // Query of requests in cert store
		KeyInfoLast = 3003,
		DeviceInfoFirst = 4000, // *******************
		DeviceInfoInitialise = 4001, // Initialise device for use
		DeviceInfoInitialize = 4001,
		DeviceInfoAuthentUser = 4002, // Authenticate user to device
		DeviceInfoAuthentSupervisor = 4003, // Authenticate supervisor to dev.
		DeviceInfoSetAuthentUser = 4004, // Set user authent.value
		DeviceInfoSetAuthentSupervisor = 4005, // Set supervisor auth.val.
		DeviceInfoZeroise = 4006, // Zeroise device
		DeviceInfoZeroize = 4006,
		DeviceInfoLoggedin = 4007, // Whether user is logged in
		DeviceInfoLabel = 4008, // Device/token label
		DeviceInfoLast = 4009,
		EnvironmentInfoFirst = 5000, // *********************
		EnvironmentInfoDatasize = 5001, // Data size information
		EnvironmentInfoCompression = 5002, // Compression information
		EnvironmentInfoContenttype = 5003, // Inner CMS content type
		EnvironmentInfoDetachedsignature = 5004, // Detached signature
		EnvironmentInfoSignatureResult = 5005, // Signature check result
		EnvironmentInfoIntegrity = 5006, // Integrity-protection level
		EnvironmentInfoPassword = 5007, // User password
		EnvironmentInfoKey = 5008, // Conventional encryption key
		EnvironmentInfoSignature = 5009, // Signature/signature check key
		EnvironmentInfoSignatureExtradata = 5010, // Extra information added to CMS sigs
		EnvironmentInfoRecipient = 5011, // Recipient email address
		EnvironmentInfoPublickey = 5012, // PKC encryption key
		EnvironmentInfoPrivatekey = 5013, // PKC decryption key
		EnvironmentInfoPrivatekeyLabel = 5014, // Label of PKC decryption key
		EnvironmentInfoOriginator = 5015, // Originator info/key
		EnvironmentInfoSessionkey = 5016, // Session key
		EnvironmentInfoHash = 5017, // Hash value
		EnvironmentInfoTimestamp = 5018, // Timestamp information
		EnvironmentInfoKeysetSigcheck = 5019, // Signature check keyset
		EnvironmentInfoKeysetEncrypt = 5020, // PKC encryption keyset
		EnvironmentInfoKeysetDecrypt = 5021, // PKC decryption keyset
		EnvironmentInfoLast = 5022,
		SessionInfoFirst = 6000, // ********************
		SessionInfoActive = 6001, // Whether session is active
		SessionInfoConnectionactive = 6002, // Whether network connection is active
		SessionInfoUsername = 6003, // User name
		SessionInfoPassword = 6004, // Password
		SessionInfoPrivatekey = 6005, // Server/client private key
		SessionInfoKeyset = 6006, // Certificate store
		SessionInfoAuthresponse = 6007, // Session authorisation OK
		SessionInfoServerName = 6008, // Server name
		SessionInfoServerPort = 6009, // Server port number
		SessionInfoServerFingerprintSha1 = 6010, // Server key fingerprint
		SessionInfoClientName = 6011, // Client name
		SessionInfoClientPort = 6012, // Client port number
		SessionInfoSession = 6013, // Transport mechanism
		SessionInfoNetworksocket = 6014, // User-supplied network socket
		SessionInfoVersion = 6015, // Protocol version
		SessionInfoRequest = 6016, // Cert.request object
		SessionInfoResponse = 6017, // Cert.response object
		SessionInfoCacertificate = 6018, // Issuing CA certificate
		SessionInfoCmpRequesttype = 6019, // Request type
		SessionInfoCmpPrivkeyset = 6020, // Private-key keyset
		SessionInfoSshChannel = 6021, // SSH current channel
		SessionInfoSshChannelType = 6022, // SSH channel type
		SessionInfoSshChannelArg1 = 6023, // SSH channel argument 1
		SessionInfoSshChannelArg2 = 6024, // SSH channel argument 2
		SessionInfoSshChannelActive = 6025, // SSH channel active
		SessionInfoSslOptions = 6026, // SSL/TLS protocol options
		SessionInfoTspMsgimprint = 6027, // TSP message imprint
		SessionInfoLast = 6028,
		UserInfoFirst = 7000, // ********************
		UserInfoPassword = 7001, // Password
		UserInfoCakeyCertsign = 7002, // CA cert signing key
		UserInfoCakeyCrlsign = 7003, // CA CRL signing key
		UserInfoCakeyRtcssign = 7004, // CA RTCS signing key
		UserInfoCakeyOcspsign = 7005, // CA OCSP signing key
		UserInfoLast = 7006,
		AttributeLast = 7006
	};

	public enum class CertificateKeyUsage {
		KeyUsageDigitalSignature = 0x001,
		KeyUsageNonrepudiation = 0x002,
		KeyUsageKeyEncipherment = 0x004,
		KeyUsageDataEncipherment = 0x008,
		KeyUsageKeyAgreement = 0x010,
		KeyUsageKeyCertSign = 0x020,
		KeyUsageCrlSign = 0x040,
		KeyUsageEncipherOnly = 0x080,
		KeyUsageDecipherOnly = 0x100,
		KeyUsageLast = 0x200 // Last possible value
	};

	public enum class CrlReason {
		CrlReasonUnspecified = 0,
		CrlReasonKeyCompromise = 1,
		CrlReasonCaCompromise = 2,
		CrlReasonAffiliationchanged = 3,
		CrlReasonSuperseded = 4,
		CrlReasonCessationOfOperation = 5,
		CrlReasonCertificatehold = 6,
		CrlReasonRemoveFromCrl = 8,
		CrlReasonPrivilegeWithdrawn = 9,
		CrlReasonAaCompromise = 10,
		CrlReasonLast = 11, // End Of Standard Crl Reasons        
		CrlReasonNeverValid = 20,
		CrlExtReasonLast = 21,

		CrlReasonFlagKeyCompromise = 0X002,
		CrlReasonFlagCaCompromise = 0X004,
		CrlReasonFlagAffiliationChanged = 0X008,
		CrlReasonFlagSuperseded = 0X010,
		CrlReasonFlagCessationOfOperation = 0X020,
		CrlReasonFlagCertificateHold = 0X040,
		CrlReasonFlagLast = 0X080 // Last Poss.Value
	};

	public enum class CrlHoldInstruction {
		HoldInstructionNone = 0,
		HoldInstructionCallissuer = 1,
		HoldInstructionReject = 2,
		HoldInstructionPickupToken = 3,
		HoldInstructionLast = 4
	};

	public enum class ComplianceLevel {
		ComplianceLevelOblivious = 0,
		ComplianceLevelReduced = 1,
		ComplianceLevelStandard = 2,
		ComplianceLevelPkixPartial = 3,
		ComplianceLevelPkixFull = 4,
		ComplianceLevelLast = 5
	};

	public enum class NetscapeCertificateExtensions {
		NsCertTypeSslclient = 0X001,
		NsCertTypeSslserver = 0X002,
		NsCertTypeSmime = 0X004,
		NsCertTypeObjectsigning = 0X008,
		NsCertTypeReserved = 0X010,
		NsCertTypeSslca = 0X020,
		NsCertTypeSmimeca = 0X040,
		NsCertTypeObjectsigningca = 0X080,
		NsCertTypeLast = 0X100 // Last possible value
	};

	public enum class SetCertificateType {
		SetCertificateTypeCard = 0x001,
		SetCertificateTypeMer = 0x002,
		SetCertificateTypePgwy = 0x004,
		SetCertificateTypeCca = 0x008,
		SetCertificateTypeMca = 0x010,
		SetCertificateTypePca = 0x020,
		SetCertificateTypeGca = 0x040,
		SetCertificateTypeBca = 0x080,
		SetCertificateTypeRca = 0x100,
		SetCertificateTypeAcq = 0x200,
		SetCertificateTypeLast = 0x400 // Last possible value
	};

	public enum class ContentType {
		None = 0,
		Data = 1,
		SignedData = 2,
		EnvelopedData = 3,
		SignedAndEnvelopedData = 4,
		DigestedData = 5,
		EncryptedData = 6,
		CompressedData = 7,
		AuthData = 8,
		AuthEnvData = 9,
		TstInfo = 10,
		SpcIndirectDataContext = 11,
		RtcsRequest = 12,
		RtcsResponse = 13,
		RtcsResponseExt = 14,
		Mrtd = 15,
		Last = 16
	};

	public enum class EssSecurityClassification {
		Unmarked = 0,
		Unclassified = 1,
		Restricted = 2,
		Confidential = 3,
		Secret = 4,
		TopSecret = 5,
		Last = 255
	};

	public enum class RtcsStatus {
		Valid = 0,
		NotValid = 1,
		NonAuthoritative = 2,
		Unknown = 3
	};

	public enum class OcspStatus {
		Notrevoked = 0,
		Revoked = 1,
		Unknown = 2
	};

	public enum class SignatureLevel {
		Signercert = 1, // Include signer cert         
		All = 2, // Include all relevant info   
		Last = 3 // Last possible sig.level type
	};

	public enum class IntegrityType {
		None = 0, // No Integrity Protection         
		MacOnly = 1, // Mac Only, No Encryption         
		Full = 2 // Encryption + ingerity protection
	};

	public enum class RequestType {
		None = 0, // No Request Type           
		Initialisation = 1, // Initialisation Request    
		Initialization = 1,
		Certificate = 2, // Certification Request     
		Keyupdate = 3, // Key Update Request        
		Revocation = 4, // Cert Revocation Request   
		Pkiboot = 5, // Pkiboot Request           
		Last = 6 // Last Possible Request Type
	};

	public enum class KeyIdType {
		None = 0, // No Key Id Type            
		Name = 1, // Key Owner Name            
		Uri = 2, // Key Owner Uri             
		Email = 2, // Synonym: Owner Email Addr.
		Last = 3 // Last Possible key ID type 
	};

	public enum class ObjectType {
		None = 0, // No object type              
		EncryptedKey = 1, // Conventionally encrypted key
		PkcEncryptedKey = 2, // PKC-encrypted key           
		KeyAgreement = 3, // Key agreement information   
		Signature = 4, // Signature                   
		Last = 5 // Last possible object type   
	};

	public enum class ErrorType {
		None = 0, // No error information                 
		AttributeSize = 1, // Attribute data too small or large    
		AttributeValue = 2, // Attribute value is invalid           
		AttributeAbsent = 3, // Required attribute missing           
		AttributePresent = 4, // Non-allowed attribute present        
		Constraint = 5, // Cert: Constraint violation in object 
		IssuerConstraint = 6, // Cert: Constraint viol.in issuing cert
		Last = 7 // Last possible error info type   
	};

	public enum class CertificateActionType {
		None = 0, // No cert management action         
		Create = 1, // Create cert store                 
		Connect = 2, // Connect to cert store             
		Disconnect = 3, // Disconnect from cert store        
		Error = 4, // Error information                 
		AddUser = 5, // Add PKI user                      
		DeleteUser = 6, // Delete PKI user                   
		RequestCertificate = 7, // Cert request                      
		RequestRenewal = 8, // Cert renewal request              
		RequestRevocation = 9, // Cert revocation request           
		CertificateCreation = 10, // Cert creation                     
		CertificateCreationComplete = 11, // Confirmation of cert creation     
		CertificateCreationDrop = 12, // Cancellation of cert creation     
		CertificateCreationReverse = 13, // Cancel of creation w.revocation   
		RestartCleanup = 14, // Delete reqs after restart         
		RestartRevokeCertificate = 15, // Complete revocation after restart 
		IssueCertificate = 16, // Cert issue                        
		IssueCrl = 17, // CRL issue                         
		RevokeCertificate = 18, // Cert revocation                   
		ExpireCertificate = 19, // Cert expiry                       
		Cleanup = 20, // Clean up on restart               
		Last = 21 // Last possible cert store log action
	};

	public enum class SslOption {
		None = 0x000,
		MinimumVersionSslv3 = 0x000, // Min.protocol version       
		MinimumVersionTls10 = 0x001,
		MinimumVersionTls11 = 0x002,
		MinimumVersionTls12 = 0x003,
		MinimumVersionTls13 = 0x004,
		ManualCertificateCheck = 0x008, // Require manual cert.verif. 
		DisableNameVerify = 0x010, // Disable cert hostname check
		DisableCertificateVerify = 0x020, // Disable certificate check  
		SuiteB128 = 0x100, // SuiteB security levels (may
		SuiteB256 = 0x200 // vanish in future releases)  
	};

	public enum KeysetOption {
		None,
		ReadOnly,
		Create,
		ExclusiveAccess,
		Last,
		LastExternal = Create + 1
	};

#pragma endregion

#pragma region Exceptions
	
	[Serializable]
	public ref class CryptographicException : public Exception
	{
	public:
		CryptographicException() : Exception() {}
		CryptographicException(String^ message) : Exception(message) {}
		CryptographicException(String^ message, Exception^ inner) : Exception(message, inner) {}

		void AddExtendedErrorInformation(ExtendedErrorInformation^ errorInfo)
		{
			Data->Add("Error Code", errorInfo->ErrorCode);
			Data->Add("Error Type", errorInfo->ErrorType);
			Data->Add("Error Locus", errorInfo->ErrorLocus);
			Data->Add("Error Description", errorInfo->ErrorDescription);
		}

	protected:
		CryptographicException(System::Runtime::Serialization::SerializationInfo^ info, System::Runtime::Serialization::StreamingContext context) : Exception(info, context) {}
	};

#pragma endregion

	public ref class Cryptography
	{
	public:
	/* Constructors */
	Cryptography();
	~Cryptography();
	Cryptography(const Cryptography%);
		

	/****************************************************************************
	*																			*
	*						Constant Values										*
	*																			*
	****************************************************************************/

	/* The maximum user key size - 2048 bits */
	static const int MaxKeySize = 256;

	/* The maximum IV/cipher block size - 256 bits */
	static const int MaxIvSize = 32;

	/* The maximum public-key component size - 4096 bits, and maximum component
	size for ECCs - 576 bits (to handle the P521 curve) */
	static const int MaxPkcSize = 512;
	static const int MaxPckSizeEcc = 72;

	/* The maximum hash size - 512 bits.  Before 3.4 this was 256 bits, in the
	3.4 release it was increased to 512 bits to accommodate SHA-3 */
	static const int MaxHashSize = 64;

	/* The maximum size of a text string (e.g.key owner name) */
	static const int MaxTextSize = 64;

	/* A magic value indicating that the default setting for this parameter
	should be used.  The parentheses are to catch potential erroneous use
	in an expression */
	static const int UseDefault = -100;

	/* A magic value for unused parameters */
	static const int Unused = -101;

	/* Cursor positioning codes for certificate/CRL extensions.  The parentheses
	are to catch potential erroneous use in an expression */
	static const int CursorFirst = -200;
	static const int CursorPrevious = -201;
	static const int CursorNext = -202;
	static const int CursorLast = -203;

	/* The type of information polling to perform to get random seed
	information.  These values have to be negative because they're used
	as magic length values for cryptAddRandom().  The parentheses are to
	catch potential erroneous use in an expression */
	static const int RandomFastPoll = -300;
	static const int RandomSlowPoll = -301;

	/* Whether the PKC key is a  or private key */

	static const int PrivateKeyType = 0;
	static const int PublicKeyType = 1;

	/* Keyset open options */
	static const int KeyOptionNone = 0; // No options
	static const int KeyOptionReadOnly = 1; // Open keyset in read-only mode
	static const int KeyOptionCreate = 2; // Create a new keyset
	static const int KeyOptionLast = 3; // Last possible key option type

	static const int EccCurveNone = 0; // No ECC curve type                       
	static const int EccCurveP256 = 1; // NIST P256/X9.62 P256v1/SECG p256r1 curve
	static const int EccCurveP384 = 2; // NIST P384, SECG p384r1 curve            
	static const int EccCurveP521 = 3; // NIST P521, SECG p521r1                  
	static const int EccCurveBrainPoolP256 = 4; // Brainpool p256r1                        
	static const int EccCurveBrainPoolP384 = 5; // Brainpool p384r1                        
	static const int EccCurveBrainPoolP512 = 6; // Brainpool p512r1                        
	static const int EccCurveLast = 7; // Last valid ECC curve type               

	/* No error in function call */
	static const int OK = 0; // No error

	/* Error in parameters passed to function.  The parentheses are to catch
	potential erroneous use in an expression */
	static const int ErrorParam1 = -1; // Bad argument, parameter 1
	static const int ErrorParam2 = -2; // Bad argument, parameter 2
	static const int ErrorParam3 = -3; // Bad argument, parameter 3
	static const int ErrorParam4 = -4; // Bad argument, parameter 4
	static const int ErrorParam5 = -5; // Bad argument, parameter 5
	static const int ErrorParam6 = -6; // Bad argument, parameter 6
	static const int ErrorParam7 = -7; // Bad argument, parameter 7

	/* Errors due to insufficient resources */
	static const int ErrorMemory = -10; // Out of memory
	static const int ErrorNotinited = -11; // Data has not been initialised
	static const int ErrorInited = -12; // Data has already been init'd
	static const int ErrorNoSecure = -13; // Opn.not avail.at requested sec.level
	static const int ErrorRandom = -14; // No reliable random data available
	static const int ErrorFailed = -15; // Operation failed
	static const int ErrorInternal = -16; // Internal consistency check failed

	/* Security violations */
	static const int ErrorNotAvail = -20; // This type of opn.not available
	static const int ErrorPermission = -21; // No permiss.to perform this operation
	static const int ErrorWrongKey = -22; // Incorrect key used to decrypt data
	static const int ErrorIncomplete = -23; // Operation incomplete/still in progress
	static const int ErrorComplete = -24; // Operation complete/can't continue
	static const int ErrorTimeout = -25; // Operation timed out before completion
	static const int ErrorInvalid = -26; // Invalid/inconsistent information
	static const int ErrorSignaled = -27; // Resource destroyed by extnl.event

	/* High-level function errors */
	static const int ErrorOverflow = -30; // Resources/space exhausted
	static const int ErrorUnderflow = -31; // Not enough data available
	static const int ErrorBadData = -32; // Bad/unrecognised data format
	static const int ErrorSignature = -33; // Signature/integrity check failed

	/* Data access function errors */
	static const int ErrorOpen = -40; // Cannot open object
	static const int ErrorRead = -41; // Cannot read item from object
	static const int ErrorWrite = -42; // Cannot write item to object
	static const int ErrorNotFound = -43; // Requested item not found in object
	static const int ErrorDuplicate = -44; // Item already present in object

	/* Data enveloping errors */
	static const int EnvelopeResource = -50; // Need resource to proceed

	/****************************************************************************
	*																			*
	*						General Functions									*
	*																			*
	****************************************************************************/
	AlgorithmCapabilities ^ QueryCapability(Algorithm algorithm);
	CryptContext CreateContext(CryptUser user, Algorithm algorithm);
	void DestroyContext(CryptContext context);
	void DestroyObject(CryptObject object);
	void GenerateKey(CryptContext context, String^ label);
	array<Byte>^ Encrypt(String^ keyId, String^ data);
	array<Byte>^ Encrypt(String^ keyId, array<Byte>^ data);
	array<Byte>^ Decrypt(CryptContext context, array<Byte>^ data, int dataLength);
	void SetAttribute(CryptHandle handle, AttributeType attributeType, int value);
	void SetAttribute(CryptHandle handle, AttributeType attributeType, String^ value);
	int GetAttribute(CryptHandle handle, AttributeType attributeType);
	String^ GetAttributeString(CryptHandle handle, AttributeType attributeType);
	void DeleteAttribute(CryptHandle handle, AttributeType attributeType);

	/****************************************************************************
	*																			*
	*						Mid-level Encryption Functions						*
	*																			*
	****************************************************************************/

	/* Export and import an encrypted session key */

	array<Byte>^ ExportKey(CryptHandle exportKey, CryptContext sessionKeyContext);
	array<Byte>^ ExportKey(CryptHandle exportKey, int maximumKeyLength, int keyLength,
		Format keyFormat, CryptHandle exportKeyHandle, CryptContext sessionKeyContext);

	CryptContext ImportKey(array<Byte>^ encryptedKey, int encryptedKeyLength, CryptContext importKeyContext,
		SessionContext sessionKeyContext);

	/* Create and check a digital signature */

	array<Byte>^ CreateSignature(int signatureMaxLength, Format formatType, CryptContext signatureContext,
		CryptContext hashContext, CryptCertificate extraData);

	CryptContext CheckSignature(array<Byte>^ signature, int signatureLength, CryptHandle signatureCheckKey, CryptContext hashContext);

	/****************************************************************************
	*																			*
	*									Keyset Functions						*
	*																			*
	****************************************************************************/

	CryptKeyset KeysetOpen(KeysetType^ keysetType, String^ name, KeysetOption keysetOptions );

	void KeysetClose(CryptKeyset keyset);

	CryptContext GetPublicKey(CryptKeyset keyset, KeyIdType keyIdType, String^ KeyId);

	CryptContext GetPrivateKey(CryptKeyset keyset, KeyIdType keyIdType, String^ keyId, String^ password);

	void AddPublicKey(CryptKeyset keyset, CryptCertificate certificate);

	void AddPrivateKey(CryptKeyset keyset, CryptHandle key, String^ password);

	void DeleteKey(CryptKeyset keyset, KeyIdType keyIdType, String^ keyId);

	/****************************************************************************
	*																			*
	*								Certificate Functions						*
	*																			*
	****************************************************************************/

	CryptCertificate CreateCertificate(CryptUser user, CertificateType certificateType);

	void DestroyCertificate(CryptCertificate certificate);

	CertificateExtension GetCertificateExtension(CryptCertificate certificate, String^ oid, int extensionMaximumLength);

	void AddCertificateExtension(CryptCertificate certificate, String^ oid, bool isCritical, String^ extension, int extensionMaximumLength);

	void DeleteCertificateExtension(CryptCertificate certificate, String^ oid);

	void SignCertificate(CryptCertificate certificate, CryptContext certificateContext);

	void CheckCertificateSignature(CryptCertificate certificate, CryptHandle signatureCheckKey);

	CryptCertificate ImportCertificate(array<Byte>^ certificateObject, int certificateObjectLength, CryptUser user);

	array<Byte>^ ExportCertificate(int certificateObjectMaxLength, CertificateType certificateType, CryptCertificate certificate);

	void AddCertificationAuthorityItem(CryptKeyset keyset, CryptCertificate certificate);

	CryptCertificate GetCertificationAuthorityItem(CryptKeyset keyset, CertificateType certificateType, KeyIdType keyIdType, String^ keyId);

	void DeleteCertificationAuthorityItem(CryptKeyset keyset, CertificateType certificateType, KeyIdType keyIdType, String^ keyId);

	CryptCertificate CertificationAuthorityManagement(CertificateActionType action, CryptKeyset keyset, CryptContext caKey, CryptCertificate certificateRequest);

	/****************************************************************************
	*																			*
	*							Envelope and Session Functions					*
	*																			*
	****************************************************************************/

	CryptEnvelope CreateEnvelope(CryptUser user, Format format);

	void DestroyEnvelope(CryptEnvelope envelope);

	void PushData(CryptHandle envelope, array<Byte>^ data);

	array<Byte>^ PopData(CryptEnvelope envelope, int length);


	/****************************************************************************
	*																			*
	*								Device Functions							*
	*																			*
	****************************************************************************/

	CryptDevice OpenDevice(CryptUser user, CryptDevice device, String^ name);

	void CloseDevice(CryptDevice device);

	QueryInfo QueryDeviceCapabilities(CryptDevice device, Algorithm algorithm);

	CryptContext CreateDeviceContext(CryptDevice device, Algorithm algorithm);


	/****************************************************************************
	*																			*
	*							User Management Functions						*
	*																			*
	****************************************************************************/

	CryptUser Login(String^ user, String^ password);

	void Logout(CryptUser user);
	};

}




