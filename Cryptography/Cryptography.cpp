// This is the main DLL file.

#include "stdafx.h"

#include "Cryptography.h"
#include <cryptlib.h>

using namespace OpenCKMS;

void EvaluateMethodResult(int result)
{
	if (result)
	{
		int errorStringLength;
		cryptGetAttributeString(result, CRYPT_ATTRIBUTE_ERRORMESSAGE, NULL, &errorStringLength);
		char *errorString = new char[errorStringLength];
		cryptGetAttributeString(result, CRYPT_ATTRIBUTE_ERRORMESSAGE, errorString, &errorStringLength);
		String^ errorDescription = gcnew String(errorString);
		throw gcnew CryptographicException(errorDescription);
		//delete errorString;
	}
}

OpenCKMS::Cryptography::Cryptography()
{
	EvaluateMethodResult(cryptInit());
}

OpenCKMS::Cryptography::~Cryptography()
{
	EvaluateMethodResult(cryptEnd());
}

AlgorithmCapabilities ^ OpenCKMS::Cryptography::QueryCapability(Algorithm algorithm)
{
	auto algorithmCapabilities = gcnew AlgorithmCapabilities();
	return algorithmCapabilities;
}

CryptContext OpenCKMS::Cryptography::CreateContext(CryptUser user, Algorithm algorithm)
{
	int context;
	int result = cryptCreateContext(&context, user, (CRYPT_ALGO_TYPE)algorithm);
	if(result) {
		switch(result) {
			case -2:
				break;
			case -3:
				break;
			default:
				String^ errorMessage = gcnew String("An error occurred in the CreateContext method.  The returned error code is " + result);
				throw gcnew CryptographicException(errorMessage);
		}
	}
	return context;
}

void OpenCKMS::Cryptography::DestroyContext(CryptContext context)
{
	EvaluateMethodResult(cryptDestroyContext(context));
}

void Cryptography::DestroyObject(CryptObject object)
{
	
}

void OpenCKMS::Cryptography::GenerateKey(CryptContext context)
{
	
}

array<System::Byte>^ OpenCKMS::Cryptography::Encrypt(CryptContext context, String^ data)
{
	auto encryptedData = gcnew array<Byte> (10);
	return encryptedData;
}

array<System::Byte>^ OpenCKMS::Cryptography::Encrypt(CryptContext context, array<Byte>^ data)
{
	auto encryptedData = gcnew array<Byte>(10);
	return encryptedData;
}

array<System::Byte>^ OpenCKMS::Cryptography::Decrypt(CryptContext context, array<Byte>^ data, int dataLength)
{
	auto encryptedData = gcnew array<Byte>(10);
	return encryptedData;
}

void OpenCKMS::Cryptography::SetAttribute(CryptHandle handle, AttributeType attributeType, int value)
{
	
}

void OpenCKMS::Cryptography::SetAttribute(CryptHandle handle, AttributeType attributeType, String^ value, int valueLength)
{
	
}

int Cryptography::GetAttribute(CryptHandle handle, AttributeType attributeType)
{
	return 0;
}

String^ OpenCKMS::Cryptography::GetAttributeString(CryptHandle handle, AttributeType attributeType)
{
	return String::Empty;
}

void OpenCKMS::Cryptography::DeleteAttribute(CryptHandle handle, AttributeType attributeType)
{
	
}

/****************************************************************************
*																			*
*						Mid-level Encryption Functions						*
*																			*
****************************************************************************/

/* Export and import an encrypted session key */

array<Byte>^ Cryptography::ExportKey(CryptHandle exportKey, CryptContext sessionKeyContext)
{
	return gcnew array<Byte>(0);
}

array<Byte>^ OpenCKMS::Cryptography::ExportKey(CryptHandle exportKey, int maximumKeyLength, int keyLength,
	Format keyFormat, CryptHandle exportKeyHandle,
	CryptContext sessionKeyContext)
{
	return gcnew array<Byte>(0);
}

CryptContext OpenCKMS::Cryptography::ImportKey(array<Byte>^ encryptedKey, int encryptedKeyLength, CryptContext importKeyContext,
	SessionContext sessionKeyContext)
{
	return 0;
}

/* Create and check a digital signature */

array<Byte>^ OpenCKMS::Cryptography::CreateSignature(int signatureMaxLength, Format formatType, CryptContext signatureContext,
	CryptContext hashContext, CryptCertificate extraData)
{
	return gcnew array<Byte>(0);
}

CryptContext OpenCKMS::Cryptography::CheckSignature(array<Byte>^ signature, int signatureLength, CryptHandle signatureCheckKey,
	CryptContext hashContext)
{
	return 0;
}

CryptKeyset OpenCKMS::Cryptography::KeysetOpen(KeysetType keysetType, String ^ name, KeysetOption keysetOptions)
{
	return CryptKeyset();
}

void OpenCKMS::Cryptography::KeysetClose(CryptKeyset keyset)
{
	throw gcnew System::NotImplementedException();
}

CryptContext OpenCKMS::Cryptography::GetPublicKey(CryptKeyset keyset, KeyIdType keyIdType, String ^ KeyId)
{
	return CryptContext();
}

CryptContext OpenCKMS::Cryptography::GetPrivateKey(CryptKeyset keyset, KeyIdType keyIdType, String ^ keyId, String ^ password)
{
	return CryptContext();
}

void OpenCKMS::Cryptography::AddPublicKey(CryptKeyset keyset, CryptCertificate certificate)
{
	throw gcnew System::NotImplementedException();
}

void OpenCKMS::Cryptography::AddPrivateKey(CryptKeyset keyset, CryptHandle key, String ^ password)
{
	throw gcnew System::NotImplementedException();
}

void OpenCKMS::Cryptography::DeleteKey(CryptKeyset keyset, KeyIdType keyIdType, String ^ keyId)
{
	throw gcnew System::NotImplementedException();
}

CryptCertificate OpenCKMS::Cryptography::CreateCertificate(CryptUser user, CertificateType certificateType)
{
	return CryptCertificate();
}

void OpenCKMS::Cryptography::DestroyCertificate(CryptCertificate certificate)
{
	throw gcnew System::NotImplementedException();
}

CertificateExtension OpenCKMS::Cryptography::GetCertificateExtension(CryptCertificate certificate, String ^ oid, int extensionMaximumLength)
{
	return CertificateExtension();
}

void OpenCKMS::Cryptography::AddCertificateExtension(CryptCertificate certificate, String ^ oid, bool isCritical, String ^ extension, int extensionMaximumLength)
{
	throw gcnew System::NotImplementedException();
}

void OpenCKMS::Cryptography::DeleteCertificateExtension(CryptCertificate certificate, String ^ oid)
{
	throw gcnew System::NotImplementedException();
}

void OpenCKMS::Cryptography::SignCertificate(CryptCertificate certificate, CryptContext certificateContext)
{
	throw gcnew System::NotImplementedException();
}

void OpenCKMS::Cryptography::CheckCertificateSignature(CryptCertificate certificate, CryptHandle signatureCheckKey)
{
	throw gcnew System::NotImplementedException();
}

CryptCertificate OpenCKMS::Cryptography::ImportCertificate(array<Byte>^ certificateObject, int certificateObjectLength, CryptUser user)
{
	return CryptCertificate();
}

array<Byte>^ OpenCKMS::Cryptography::ExportCertificate(int certificateObjectMaxLength, CertificateType certificateType, CryptCertificate certificate)
{
	throw gcnew System::NotImplementedException();
	// TODO: insert return statement here
}

void OpenCKMS::Cryptography::AddCertificationAuthorityItem(CryptKeyset keyset, CryptCertificate certificate)
{
	throw gcnew System::NotImplementedException();
}

CryptCertificate OpenCKMS::Cryptography::GetCertificationAuthorityItem(CryptKeyset keyset, CertificateType certificateType, KeyIdType keyIdType, String ^ keyId)
{
	return CryptCertificate();
}

void OpenCKMS::Cryptography::DeleteCertificationAuthorityItem(CryptKeyset keyset, CertificateType certificateType, KeyIdType keyIdType, String ^ keyId)
{
	throw gcnew System::NotImplementedException();
}

CryptCertificate OpenCKMS::Cryptography::CertificationAuthorityManagement(CertificateActionType action, CryptKeyset keyset, CryptContext caKey, CryptCertificate certificateRequest)
{
	return CryptCertificate();
}

CryptEnvelope OpenCKMS::Cryptography::CreateEnvelope(CryptUser user, EnvelopeFormat format)
{
	return CryptEnvelope();
}

void OpenCKMS::Cryptography::DestroyEnvelope(CryptEnvelope envelope)
{
	throw gcnew System::NotImplementedException();
}

void OpenCKMS::Cryptography::PushData(CryptHandle envelope, array<Byte>^ data)
{
	throw gcnew System::NotImplementedException();
}

array<Byte>^ OpenCKMS::Cryptography::PopData(CryptEnvelope envelope, int length)
{
	throw gcnew System::NotImplementedException();
	// TODO: insert return statement here
}

CryptDevice OpenCKMS::Cryptography::OpenDevice(CryptUser user, CryptDevice device, String ^ name)
{
	return CryptDevice();
}

void OpenCKMS::Cryptography::CloseDevice(CryptDevice device)
{
	throw gcnew System::NotImplementedException();
}

QueryInfo OpenCKMS::Cryptography::QueryDeviceCapabilities(CryptDevice device, Algorithm algorithm)
{
	return QueryInfo();
}

CryptContext OpenCKMS::Cryptography::CreateDeviceContext(CryptDevice device, Algorithm algorithm)
{
	return CryptContext();
}

CryptUser OpenCKMS::Cryptography::Login(String ^ user, String ^ password)
{
	return CryptUser();
}

void OpenCKMS::Cryptography::Logout(CryptUser user)
{
	throw gcnew System::NotImplementedException();
}

