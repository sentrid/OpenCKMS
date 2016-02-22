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
            crypto.GenerateKey(ctx, "MyNewKey");
            var theKey = crypto.ExportKey(ctx, ctx);
            crypto.DestroyContext(ctx);
        }
    }
}
