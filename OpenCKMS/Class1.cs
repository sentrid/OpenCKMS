using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenCKMS
{
    public class Class1
    {
        public void T()
        {
            var c = new Cryptography();
            var context = c.CreateContext(0, Algorithm.Dh);
        }
    }
}
