using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenCKMS;

namespace CryptographyTests
{
    [TestClass]
    public class CertificateTests
    {
        [TestMethod]
        public void CertificateShouldBeCreatedWithoutErrors()
        {
            var cryptography = new Cryptography();
            cryptography.GenerateKeyPair("MyName");
        } 
    }
}