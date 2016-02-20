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

