using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace RNCryptor
{
    public class Decryptor : Cryptor
    {
        public byte[] Decrypt(byte[] encryptedBytes, string password)
        {
            PayloadComponents components = unpackEncryptedData(encryptedBytes);

            if (!hmacIsValid(components, password))
                return null;

            byte[] key = generateKey(components.salt, password);

            byte[] plaintextBytes = new byte[0];

            switch (aesMode)
            {
                case AesMode.CTR:
                    // Yes, we are "encrypting" here.  CTR uses the same code in both directions.
                    plaintextBytes = encryptAesCtrLittleEndianNoPadding(components.ciphertext, key, components.iv);
                    break;

                case AesMode.CBC:
                    plaintextBytes = decryptAesCbcPkcs7(components.ciphertext, key, components.iv);
                    break;
            }

            return plaintextBytes;
        }

        private byte[] decryptAesCbcPkcs7(byte[] encrypted, byte[] key, byte[] iv)
        {
            var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            var decryptor = aes.CreateDecryptor(key, iv);

            byte[] plainBytes;
            using (MemoryStream msDecrypt = new MemoryStream())
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                {
                    csDecrypt.Write(encrypted, 0, encrypted.Length);
                    csDecrypt.FlushFinalBlock();
                    plainBytes = msDecrypt.ToArray();
                }
            }

            return plainBytes;
        }

        private PayloadComponents unpackEncryptedData(byte[] encryptedBytes)
        {
            List<byte> binaryBytes = new List<byte>();
            binaryBytes.AddRange(encryptedBytes);

            PayloadComponents components;
            int offset = 0;

            components.schema = binaryBytes.GetRange(0, 1).ToArray();
            offset++;

            configureSettings((Schema)binaryBytes[0]);

            components.options = binaryBytes.GetRange(1, 1).ToArray();
            offset++;

            components.salt = binaryBytes.GetRange(offset, saltLength).ToArray();
            offset += components.salt.Length;

            components.hmacSalt = binaryBytes.GetRange(offset, saltLength).ToArray();
            offset += components.hmacSalt.Length;

            components.iv = binaryBytes.GetRange(offset, ivLength).ToArray();
            offset += components.iv.Length;

            components.headerLength = offset;

            components.ciphertext = binaryBytes.GetRange(offset, binaryBytes.Count - hmac_length - components.headerLength).ToArray();
            offset += components.ciphertext.Length;

            components.hmac = binaryBytes.GetRange(offset, hmac_length).ToArray();

            return components;

        }

        private bool hmacIsValid(PayloadComponents components, string password)
        {
            byte[] generatedHmac = generateHmac(components, password);

            if (generatedHmac.Length != components.hmac.Length)
                return false;

            for (int i = 0; i < components.hmac.Length; i++)
            {
                if (generatedHmac[i] != components.hmac[i])
                    return false;
            }
            return true;
        }

    }
}

