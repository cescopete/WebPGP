using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System;
using System.IO;

namespace WebPGP.Util.OpenPgp
{
    public class Encryptor
    {
        private static Keys _encryptionKeys;
        private const int BUFFER_SIZE = 0x10000;

        public static void Encrypt(
            string inputPath,
            string publicKey,
            string privateKey,
            string passPhrase,
            string outputPath)
        {
            if (!File.Exists(inputPath))
                throw new FileNotFoundException(string.Format("Encrypted File [{0}] not found.", inputPath));

            if (string.IsNullOrWhiteSpace(publicKey))
                throw new FileNotFoundException(string.Format("Invalid public key.", publicKey));

            if (string.IsNullOrWhiteSpace(privateKey))
                throw new FileNotFoundException(string.Format("Invalid private key.", privateKey));

            if (string.IsNullOrWhiteSpace(outputPath))
                throw new ArgumentNullException("Invalid Output file path.");

            _encryptionKeys = new Keys(publicKey, privateKey, passPhrase);

            if (_encryptionKeys == null)
                throw new ArgumentNullException("encryptionKeys", "encryptionKeys is null.");

            FileInfo unencryptedFileInfo = new FileInfo(inputPath);
            using (Stream outputStream = File.Create(outputPath))
            {
                EncryptAndSign(outputStream, unencryptedFileInfo);
            }
        }

        private static void EncryptAndSign(Stream outputStream, FileInfo unencryptedFileInfo)
        {
            if (outputStream == null)
                throw new ArgumentNullException("outputStream", "outputStream is null.");

            if (unencryptedFileInfo == null)
                throw new ArgumentNullException("unencryptedFileInfo", "unencryptedFileInfo is null.");

            if (!File.Exists(unencryptedFileInfo.FullName))
                throw new ArgumentException("File to encrypt not found.");

            using (Stream encryptedOut = ChainEncryptedOut(outputStream))
            using (Stream compressedOut = ChainCompressedOut(encryptedOut))
            {
                PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
                using (Stream literalOut = ChainLiteralOut(compressedOut, unencryptedFileInfo))
                using (FileStream inputFile = unencryptedFileInfo.OpenRead())
                {
                    WriteOutputAndSign(compressedOut, literalOut, inputFile, signatureGenerator);
                }
            }
        }

        private static void WriteOutputAndSign(Stream compressedOut,
            Stream literalOut,
            FileStream inputFile,
            PgpSignatureGenerator signatureGenerator)
        {
            byte[] buf = new byte[BUFFER_SIZE];
            int length;
            while ((length = inputFile.Read(buf, 0, buf.Length)) > 0)
            {
                literalOut.Write(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }
            signatureGenerator.Generate().Encode(compressedOut);
        }

        private static Stream ChainEncryptedOut(Stream outputStream)
        {
            PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.TripleDes, new SecureRandom());
            encryptedDataGenerator.AddMethod(_encryptionKeys.PublicKey);
            return encryptedDataGenerator.Open(outputStream, new byte[BUFFER_SIZE]);
        }

        private static Stream ChainCompressedOut(Stream encryptedOut)
        {
            PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
            return compressedDataGenerator.Open(encryptedOut);
        }

        private static Stream ChainLiteralOut(Stream compressedOut, FileInfo file)
        {
            PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
            return pgpLiteralDataGenerator.Open(compressedOut, PgpLiteralData.Binary, file);
        }

        private static PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut)
        {
            const bool IsCritical = false;
            const bool IsNested = false;
            PublicKeyAlgorithmTag tag = _encryptionKeys.SecretKey.PublicKey.Algorithm;
            PgpSignatureGenerator pgpSignatureGenerator =
                new PgpSignatureGenerator(tag, HashAlgorithmTag.Sha1);
            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, _encryptionKeys.PrivateKey);
            foreach (string userId in _encryptionKeys.SecretKey.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator subPacketGenerator =
                   new PgpSignatureSubpacketGenerator();
                subPacketGenerator.SetSignerUserId(IsCritical, userId);
                pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
                break;
            }
            pgpSignatureGenerator.GenerateOnePassVersion(IsNested).Encode(compressedOut);
            return pgpSignatureGenerator;
        }
    }
}
