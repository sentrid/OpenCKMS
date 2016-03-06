using System.Security;

namespace InstallationTasks
{
    public class CertificateConfig
    {
        public string CaCertificateStore { get; set; }
        public string CaKeyStoreName { get; set; }
        public SecureString CaPrivateKeyPassword { get; set; }
        public string Country { get; set; }
        public string Organization { get; set; }
        public string OrganizationalUnit { get; set; }
        public string CommonName { get; set; }
    }
}