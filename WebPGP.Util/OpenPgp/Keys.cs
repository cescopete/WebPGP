using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace WebPGP.Util.OpenPgp
{
    public class Keys
    {
        public PgpPublicKey PublicKey { get; private set; }
        public PgpPrivateKey PrivateKey { get; private set; }
        public PgpSecretKey SecretKey { get; private set; }

        public Keys(string publicKey, string privateKey, string passPhrase)
        {
            PublicKey = ReadPublicKey(publicKey);
            SecretKey = ReadSecretKey(privateKey);
            PrivateKey = ReadPrivateKey(passPhrase);
        }

        #region Public Key
        private PgpPublicKey ReadPublicKey(string publicKey)
        {
            byte[] buffer = Encoding.ASCII.GetBytes(publicKey);

            using (Stream keyIn = new MemoryStream(buffer))
            {
                using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
                {
                    PgpPublicKeyRingBundle publicKeyRingBundle = new PgpPublicKeyRingBundle(inputStream);
                    PgpPublicKey foundKey = GetFirstPublicKey(publicKeyRingBundle);
                    if (foundKey != null)
                        return foundKey;
                }
            }

            throw new ArgumentException("No encryption key found in public key ring.");
        }
        private PgpPublicKey GetFirstPublicKey(PgpPublicKeyRingBundle publicKeyRingBundle)
        {
            foreach (PgpPublicKeyRing kRing in publicKeyRingBundle.GetKeyRings())
            {
                PgpPublicKey key = kRing.GetPublicKeys()
                    .Cast<PgpPublicKey>()
                    .Where(k => k.IsEncryptionKey)
                    .FirstOrDefault();
                if (key != null)
                    return key;
            }
            return null;
        }
        #endregion

        #region Secret Key
        private PgpSecretKey ReadSecretKey(string privateKey)
        {
            byte[] buffer = Encoding.ASCII.GetBytes(privateKey);

            using (Stream keyIn = new MemoryStream(buffer))
            {
                using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
                {
                    PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(inputStream);
                    PgpSecretKey foundKey = GetFirstSecretKey(secretKeyRingBundle);
                    if (foundKey != null)
                        return foundKey;
                }
            }

            throw new ArgumentException("Can't find signing key in key ring.");
        }
        private PgpSecretKey GetFirstSecretKey(PgpSecretKeyRingBundle secretKeyRingBundle)
        {
            foreach (PgpSecretKeyRing kRing in secretKeyRingBundle.GetKeyRings())
            {
                PgpSecretKey key = kRing.GetSecretKeys()
                    .Cast<PgpSecretKey>()
                    .Where(k => k.IsSigningKey)
                    .FirstOrDefault();

                if (key != null)
                    return key;
            }

            return null;
        }
        #endregion

        #region Private Key
        private PgpPrivateKey ReadPrivateKey(string passPhrase)
        {
            PgpPrivateKey privateKey = SecretKey.ExtractPrivateKey(passPhrase.ToCharArray());

            if (privateKey != null)
            {
                return privateKey;
            }

            throw new ArgumentException("No private key found in secret key.");
        }
        #endregion
    }
}
