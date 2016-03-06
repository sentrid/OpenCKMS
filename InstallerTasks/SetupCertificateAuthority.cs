using InstallationTasks;

namespace InstallerTasks
{
    public class SetupCertificateAuthority
    {
        public static void CreateCertificateAuthority(CertificateConfig config)
        {
            Cryptography.Init();
            /* Create the CA KeyStore DB*/
            var caKeyStore = Cryptography.KeysetOpen(Cryptography.UNUSED, Cryptography.KEYSET_ODBC_STORE, config.CaCertificateStore,
                Cryptography.KEYOPT_CREATE);

            /* Create the Root CA Private Key */
            var caRootCertContext = Cryptography.CreateContext(Cryptography.UNUSED, Cryptography.ALGO_RSA);
            Cryptography.SetAttributeString(caRootCertContext, Cryptography.CTXINFO_LABEL, "CaPrivateKey");
            Cryptography.GenerateKey(caRootCertContext);

            /* Create the CA certificate and add the public key */
            var caCert = Cryptography.CreateCert(Cryptography.UNUSED, Cryptography.CERTTYPE_CERTIFICATE);
            Cryptography.SetAttribute(caCert, Cryptography.CERTINFO_SUBJECTPUBLICKEYINFO, caRootCertContext);
            Cryptography.SetAttributeString(caCert, Cryptography.CERTINFO_COUNTRYNAME, config.Country);
            Cryptography.SetAttributeString(caCert, Cryptography.CERTINFO_ORGANIZATIONNAME, config.Organization);
            Cryptography.SetAttributeString(caCert, Cryptography.CERTINFO_ORGANIZATIONALUNITNAME, config.OrganizationalUnit);
            Cryptography.SetAttributeString(caCert, Cryptography.CERTINFO_COMMONNAME, config.CommonName);

            /* Self Sign the Cert */
            Cryptography.SetAttribute(caCert, Cryptography.CERTINFO_SELFSIGNED, 1);
            Cryptography.SetAttribute(caCert, Cryptography.CERTINFO_CA, 1);

            //Cryptography.SetAttribute(caCert, Cryptography.CERTINFO_AUTHORITYINFO_CERTSTORE, Cryptography.UNUSED);
            //Cryptography.SetAttributeString(caCert, Cryptography.CERTINFO_UNIFORMRESOURCEIDENTIFIER, "http://localhost/ca/certstore");
            //Cryptography.SetAttribute(caCert, Cryptography.CERTINFO_AUTHORITYINFO_RTCS, Cryptography.UNUSED);
            //Cryptography.SetAttributeString(caCert, Cryptography.CERTINFO_UNIFORMRESOURCEIDENTIFIER, "http://localhost/ca/rtcs");

            Cryptography.SignCert(caCert, caRootCertContext);

            var cryptKeyset = Cryptography.KeysetOpen(Cryptography.UNUSED, Cryptography.KEYSET_FILE, config.CaKeyStoreName, Cryptography.KEYOPT_CREATE);
            Cryptography.AddPrivateKey(cryptKeyset, caRootCertContext, config.CaPrivateKeyPassword.ToString());
            Cryptography.AddPublicKey(cryptKeyset, caCert);
            Cryptography.KeysetClose(cryptKeyset);
            Cryptography.KeysetClose(caKeyStore);
            Cryptography.DestroyContext(caRootCertContext);
            Cryptography.DestroyCert(caCert);

            Cryptography.End();
        }
    }
}