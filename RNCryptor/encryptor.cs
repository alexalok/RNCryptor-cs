using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace RNCryptor
{
    public class Encryptor : Cryptor
    {
        private Schema defaultSchemaVersion = Schema.V2;

        public byte[] Encrypt(byte[] plainBytes, string password)
        {
            return Encrypt(plainBytes, password, defaultSchemaVersion);
        }

        public byte[] Encrypt(byte[] plainBytes, string password, Schema schemaVersion)
        {
            configureSettings(schemaVersion);


            PayloadComponents components = new PayloadComponents();
            components.schema = new byte[] { (byte)schemaVersion };
            components.options = new byte[] { (byte)options };
            components.salt = generateRandomBytes(saltLength);
            components.hmacSalt = generateRandomBytes(saltLength);
            components.iv = generateRandomBytes(ivLength);

            byte[] key = generateKey(components.salt, password);

            switch (aesMode)
            {
                case AesMode.CTR:
                    components.ciphertext = encryptAesCtrLittleEndianNoPadding(plainBytes, key, components.iv);
                    break;

                case AesMode.CBC:
                    components.ciphertext = encryptAesCbcPkcs7(plainBytes, key, components.iv);
                    break;
            }

            components.hmac = generateHmac(components, password);

            List<byte> binaryBytes = new List<byte>();
            binaryBytes.AddRange(assembleHeader(components));
            binaryBytes.AddRange(components.ciphertext);
            binaryBytes.AddRange(components.hmac);

            return binaryBytes.ToArray();
        }

        private byte[] encryptAesCbcPkcs7(byte[] plaintext, byte[] key, byte[] iv)
        {
            var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            var encryptor = aes.CreateEncryptor(key, iv);

            byte[] encrypted;

            using (var ms = new MemoryStream())
            {
                using (var cs1 = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs1.Write(plaintext, 0, plaintext.Length);
                }

                encrypted = ms.ToArray();
            }

            return encrypted;
        }

        private byte[] generateRandomBytes(int length)
        {
            byte[] randomBytes = new byte[length];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(randomBytes);

            return randomBytes;
        }
    }
}

