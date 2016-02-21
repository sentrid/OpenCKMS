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

Cryptography::Cryptography()
{
	EvaluateMethodResult(cryptInit());
}

Cryptography::~Cryptography()
{
	EvaluateMethodResult(cryptEnd());
}

AlgorithmCapabilities ^ Cryptography::QueryCapability(Algorithm algorithm)
{
	auto algorithmCapabilities = gcnew AlgorithmCapabilities();
	return algorithmCapabilities;
}

CryptContext Cryptography::CreateContext(CryptUser user, Algorithm algorithm)
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

void Cryptography::DestroyContext(CryptContext context)
{
	EvaluateMethodResult(cryptDestroyContext(context));
}

void Cryptography::DestroyObject(CryptObject object)
{
	
}

void Cryptography::GenerateKey(CryptContext context)
{
	
}

array<System::Byte>^ Cryptography::Encrypt(CryptContext context, String^ data)
{
	auto encryptedData = gcnew array<Byte> (10);
	return encryptedData;
}

array<System::Byte>^ Cryptography::Encrypt(CryptContext context, array<Byte>^ data)
{
	auto encryptedData = gcnew array<Byte>(10);
	return encryptedData;
}

array<System::Byte>^ Cryptography::Decrypt(CryptContext context, array<Byte>^ data, int dataLength)
{
	auto encryptedData = gcnew array<Byte>(10);
	return encryptedData;
}

void Cryptography::SetAttribute(CryptHandle handle, AttributeType attributeType, int value)
{
	
}

void Cryptography::SetAttribute(CryptHandle handle, AttributeType attributeType, String^ value, int valueLength)
{
	
}

int Cryptography::GetAttribute(CryptHandle handle, AttributeType attributeType)
{
	return 0;
}

String^ Cryptography::GetAttributeString(CryptHandle handle, AttributeType attributeType)
{
	return String::Empty;
}

void Cryptography::DeleteAttribute(CryptHandle handle, AttributeType attributeType)
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

array<Byte>^ Cryptography::ExportKey(CryptHandle exportKey, int maximumKeyLength, int keyLength,
	Format keyFormat, CryptHandle exportKeyHandle,
	CryptContext sessionKeyContext)
{
	return gcnew array<Byte>(0);
}

CryptContext Cryptography::ImportKey(array<Byte>^ encryptedKey, int encryptedKeyLength, CryptContext importKeyContext,
	SessionContext sessionKeyContext)
{
	return 0;
}

/* Create and check a digital signature */

array<Byte>^ Cryptography::CreateSignature(int signatureMaxLength, Format formatType, CryptContext signatureContext,
	CryptContext hashContext, CryptCertificate extraData)
{
	return gcnew array<Byte>(0);
}

CryptContext Cryptography::CheckSignature(array<Byte>^ signature, int signatureLength, CryptHandle signatureCheckKey, 
	CryptContext hashContext)
{
	return 0;
}