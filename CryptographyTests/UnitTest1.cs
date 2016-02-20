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
            var cc = new Cryptography().CreateContext(0, Algorithm.Dh);
        }
    }
}
