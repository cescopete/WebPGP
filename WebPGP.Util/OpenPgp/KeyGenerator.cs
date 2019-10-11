using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Text;

namespace WebPGP.Util.OpenPgp
{
    public class KeyGenerator
    {
        public static void GenerateKeys(
            string userName,
            string passPhrase,
            out string publicKey,
            out string privateKey)
        {
            IAsymmetricCipherKeyPairGenerator keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), 1024, 8));
            AsymmetricCipherKeyPair keyPair = keyGen.GenerateKeyPair();
            ExportKeyPair(keyPair, userName, passPhrase.ToCharArray(), out publicKey, out privateKey);
        }

        private static void ExportKeyPair(
            AsymmetricCipherKeyPair keyPair,
            string userName,
            char[] passPhrase,
            out string publicKey,
            out string privateKey)
        {
            PgpSecretKey secretKey = new PgpSecretKey(
                PgpSignature.DefaultCertification,
                PublicKeyAlgorithmTag.RsaGeneral,
                keyPair.Public,
                keyPair.Private,
                DateTime.Now,
                userName,
                SymmetricKeyAlgorithmTag.Cast5,
                passPhrase,
                null,
                null,
                new SecureRandom());

            using (MemoryStream stream = new MemoryStream())
            {
                using (ArmoredOutputStream outStream = new ArmoredOutputStream(stream))
                {
                    secretKey.Encode(outStream);
                }
                privateKey = Encoding.ASCII.GetString(stream.ToArray());
            }

            using (MemoryStream stream = new MemoryStream())
            {
                using (ArmoredOutputStream outStream = new ArmoredOutputStream(stream))
                {
                    secretKey.PublicKey.Encode(outStream);
                }
                publicKey = Encoding.ASCII.GetString(stream.ToArray());
            }
        }
    }
}
