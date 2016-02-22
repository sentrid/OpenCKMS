using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenCKMS;

namespace CryptographyTests
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
            var crypto = new Cryptography();
            var ctx = crypto.CreateContext(Cryptography.Unused, Algorithm.Rsa);

            crypto.DestroyContext(ctx);
        }
    }
}
