using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;

namespace RNCryptor.Test
{
    public class TestRunner
    {
        private int completedTests = 0;
        private int failedTests = 0;
        private int nonImplementedTests = 0;
        private int passedTests = 0;

        public void run()
        {
            // RNCryptor Tests
            this.testCanDecryptSelfEncryptedDefaultVersion();
            this.testCanDecryptSelfEncryptedStringEqualToBlockSizeMultiple();
            this.testCanDecryptSelfEncryptedVersion0();
            this.testCanDecryptSelfEncryptedVersion1();
            this.testCanDecryptSelfEncryptedVersion2();
            this.testCanDecryptLongText();
            this.testCannotUseWithUnsupportedSchemaVersions();

            // Decryptor Tests
            this.testCanDecryptIosEncryptedVersion0WithPlaintextLengthLessThanOneBlock();
            this.testCanDecryptIosEncryptedVersion0WithPlaintextReallyLong();
            this.testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyOneBlock();
            this.testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyTwoBlocks();
            this.testCanDecryptIosEncryptedVersion0WithPlaintextLengthNotOnBlockInterval();
            this.testCanDecryptIosEncryptedVersion1WithPlaintextReallyLong();
            this.testCanDecryptIosEncryptedVersion1WithPlaintextLengthExactlyOneBlock();
            this.testCanDecryptIosEncryptedVersion1WithPlaintextLengthNotOnBlockInterval();
            this.testCanDecryptIosEncryptedVersion2WithPlaintextReallyLong();
            this.testCanDecryptIosEncryptedVersion2WithPlaintextLengthExactlyOneBlock();
            this.testCanDecryptIosEncryptedVersion2WithPlaintextLengthNotOnBlockInterval();
            this.testDecryptingWithBadPasswordFails();

            // Encryptor Tests
            this.testCanEncryptWithDefaultVersion();
            this.testCanEncryptWithVersion0();
            this.testCanEncryptWithVersion1();
            this.testCanEncryptWithVersion2();
            this.testSelfEncryptedVersion0VectorIsVersion0();
            this.testSelfEncryptedVersion1VectorIsVersion1();
            this.testSelfEncryptedVersion2VectorIsVersion2();

            Console.WriteLine();

            if (this.passedTests != this.completedTests)
            {
                Console.WriteLine("ERROR (" + this.completedTests + " tests, " + this.passedTests + " passed, " + this.failedTests + " failed, " + this.nonImplementedTests + " unimplemented)");
            }
            else
            {
                Console.WriteLine("OK (" + this.passedTests + " tests)");
            }
            Console.WriteLine();
        }

        private void testCanDecryptSelfEncryptedDefaultVersion()
        {
            this.performSymmetricTest(MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A);
        }

        private void testCanDecryptSelfEncryptedStringEqualToBlockSizeMultiple()
        {
            this.performSymmetricTest(MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT_V2_BLOCKSIZE, TestStrings.SAMPLE_PASSWORD_A);
        }

        private void testCanDecryptSelfEncryptedVersion0()
        {
            this.performSymmetricTestWithExplicitSchema(MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V0);
        }

        private void testCanDecryptSelfEncryptedVersion1()
        {
            this.performSymmetricTestWithExplicitSchema(MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V1);
        }

        private void testCanDecryptSelfEncryptedVersion2()
        {
            this.performSymmetricTestWithExplicitSchema(MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V2);
        }

        private void testCanDecryptLongText()
        {
            this.performSymmetricTest(MethodBase.GetCurrentMethod().Name, TestStrings.PLAINTEXT_REALLY_LONG, TestStrings.SAMPLE_PASSWORD_A);
        }

        private void testCannotUseWithUnsupportedSchemaVersions()
        {

            Encryptor encryptor = new Encryptor();
            var bytes = Encoding.UTF8.GetBytes(TestStrings.SAMPLE_PLAINTEXT);
            byte[] encrypted = encryptor.Encrypt(bytes, TestStrings.SAMPLE_PASSWORD_A);

            encrypted[0] = 0x03;

            Decryptor decryptor = new Decryptor();
            byte[] decrypted = decryptor.Decrypt(encrypted, TestStrings.SAMPLE_PASSWORD_A);

            reportSuccess(MethodBase.GetCurrentMethod().Name, decrypted == null);
        }

        // Decryptor Tests
        private void testCanDecryptIosEncryptedVersion0WithPlaintextLengthLessThanOneBlock()
        {
            this.performDecryptionTest(MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V0_LESS_THAN_ONE_BLOCK, TestStrings.PLAINTEXT_V0_LESS_THAN_ONE_BLOCK, TestStrings.IOS_PASSWORD);
        }

        private void testCanDecryptIosEncryptedVersion0WithPlaintextReallyLong()
        {
            this.performDecryptionTest(MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V0_REALLY_LONG, TestStrings.PLAINTEXT_REALLY_LONG, TestStrings.IOS_PASSWORD);
        }

        private void testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyOneBlock()
        {
            this.performDecryptionTest(MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V0_EXACTLY_ONE_BLOCK, TestStrings.PLAINTEXT_V0_EXACTLY_ONE_BLOCK, TestStrings.IOS_PASSWORD);
        }

        private void testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyTwoBlocks()
        {
            this.performDecryptionTest(MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V0_EXACTLY_TWO_BLOCKS, TestStrings.PLAINTEXT_V0_EXACTLY_TWO_BLOCKS, TestStrings.IOS_PASSWORD);
        }

        private void testCanDecryptIosEncryptedVersion0WithPlaintextLengthNotOnBlockInterval()
        {
            this.performDecryptionTest(MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V0_NON_BLOCK_INTERVAL, TestStrings.PLAINTEXT_V0_NON_BLOCK_INTERVAL, TestStrings.IOS_PASSWORD);
        }

        private void testCanDecryptIosEncryptedVersion1WithPlaintextReallyLong()
        {
            this.performDecryptionTest(MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V1_REALLY_LONG, TestStrings.PLAINTEXT_REALLY_LONG, TestStrings.IOS_PASSWORD);
        }

        private void testCanDecryptIosEncryptedVersion1WithPlaintextLengthExactlyOneBlock()
        {
            this.performDecryptionTest(MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V1_EXACTLY_ONE_BLOCK, TestStrings.PLAINTEXT_V1_EXACTLY_ONE_BLOCK, TestStrings.IOS_PASSWORD);
        }

        private void testCanDecryptIosEncryptedVersion1WithPlaintextLengthNotOnBlockInterval()
        {
            this.performDecryptionTest(MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V1_NON_BLOCK_INTERVAL, TestStrings.PLAINTEXT_V1_NON_BLOCK_INTERVAL, TestStrings.IOS_PASSWORD);
        }

        private void testCanDecryptIosEncryptedVersion2WithPlaintextReallyLong()
        {
            this.performDecryptionTest(MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V2_REALLY_LONG, TestStrings.PLAINTEXT_REALLY_LONG, TestStrings.IOS_PASSWORD);
        }

        private void testCanDecryptIosEncryptedVersion2WithPlaintextLengthExactlyOneBlock()
        {
            this.performDecryptionTest(MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V2_EXACTLY_ONE_BLOCK, TestStrings.PLAINTEXT_V2_EXACTLY_ONE_BLOCK, TestStrings.IOS_PASSWORD);
        }

        private void testCanDecryptIosEncryptedVersion2WithPlaintextLengthNotOnBlockInterval()
        {
            this.performDecryptionTest(MethodBase.GetCurrentMethod().Name, TestStrings.IOS_ENCRYPTED_V2_NON_BLOCK_INTERVAL, TestStrings.PLAINTEXT_V2_NON_BLOCK_INTERVAL, TestStrings.IOS_PASSWORD);
        }

        private void testDecryptingWithBadPasswordFails()
        {
            Decryptor cryptor = new Decryptor();
            var bytes = Encoding.UTF8.GetBytes(TestStrings.IOS_ENCRYPTED_V2_NON_BLOCK_INTERVAL);
            var decrypted = cryptor.Decrypt(bytes, "bad-password");

            reportSuccess(MethodBase.GetCurrentMethod().Name, decrypted == null);
        }

        // Encryptor Tests

        private void testCanEncryptWithDefaultVersion()
        {
            this.performEncryptionTest(MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A);
        }

        private void testCanEncryptWithVersion0()
        {
            this.performEncryptionTestWithExplicitSchema(MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V0);
        }

        private void testCanEncryptWithVersion1()
        {
            this.performEncryptionTestWithExplicitSchema(MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V1);
        }

        private void testCanEncryptWithVersion2()
        {
            this.performEncryptionTestWithExplicitSchema(MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V2);
        }

        private void testSelfEncryptedVersion0VectorIsVersion0()
        {
            this.performEncryptionTestWithSchemaCheck(MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V0);
        }

        private void testSelfEncryptedVersion1VectorIsVersion1()
        {
            this.performEncryptionTestWithSchemaCheck(MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V1);
        }

        private void testSelfEncryptedVersion2VectorIsVersion2()
        {
            this.performEncryptionTestWithSchemaCheck(MethodBase.GetCurrentMethod().Name, TestStrings.SAMPLE_PLAINTEXT, TestStrings.SAMPLE_PASSWORD_A, Schema.V2);
        }

        private void performSymmetricTest(string functionName, string plainText, string password)
        {
            Encryptor encryptor = new Encryptor();
            var plaintextBytes = Encoding.UTF8.GetBytes(plainText);
            var encrypted = encryptor.Encrypt(plaintextBytes, password);

            Decryptor decryptor = new Decryptor();
            var decrypted = decryptor.Decrypt(encrypted, password);
            var decryptedString = Encoding.UTF8.GetString(decrypted);

            reportSuccess(functionName, decryptedString == plainText);
        }

        private void performSymmetricTestWithExplicitSchema(string functionName, string plainText, string password,
            Schema schemaVersion)
        {
            Encryptor encryptor = new Encryptor();
            var plaintextBytes = Encoding.UTF8.GetBytes(plainText);
            var encryptedB64 = encryptor.Encrypt(plaintextBytes, password, schemaVersion);

            Decryptor decryptor = new Decryptor();
            var decrypted = decryptor.Decrypt(encryptedB64, password);
            var decryptedString = Encoding.UTF8.GetString(decrypted);

            reportSuccess(functionName, plainText == decryptedString);
        }

        private void performDecryptionTest(string functionName, string encrypted, string expected, string password)
        {
            Decryptor cryptor = new Decryptor();
            var bytes = Convert.FromBase64String(encrypted);
            var decrypted = cryptor.Decrypt(bytes, password);
            var decryptedString = Encoding.UTF8.GetString(decrypted);

            reportSuccess(functionName, decryptedString == expected);
        }

        private void performEncryptionTest(string functionName, string plaintext, string password)
        {
            Encryptor cryptor = new Encryptor();
            var bytes = Encoding.UTF8.GetBytes(plaintext);
            var encrypted = cryptor.Encrypt(bytes, password);
            var encryptedString = Encoding.UTF8.GetString(encrypted);

            reportSuccess(functionName, encryptedString != "" && encryptedString != plaintext);
        }

        private void performEncryptionTestWithExplicitSchema(string functionName, string plaintext, string password, Schema schemaVersion)
        {
            Encryptor cryptor = new Encryptor();
            var bytes = Encoding.UTF8.GetBytes(plaintext);
            var encrypted = cryptor.Encrypt(bytes, password, schemaVersion);
            var encryptedString = Encoding.UTF8.GetString(encrypted);

            reportSuccess(functionName, encryptedString != "" && encryptedString != plaintext);
        }

        private void performEncryptionTestWithSchemaCheck(string functionName, string plaintext, string password, Schema schemaVersion)
        {
            Encryptor cryptor = new Encryptor();
            var bytes = Encoding.UTF8.GetBytes(plaintext);
            var encrypted = cryptor.Encrypt(bytes, password, schemaVersion);

            Schema actualSchemaVersion = (Schema)encrypted[0];
            this.reportSuccess(functionName, actualSchemaVersion == schemaVersion);
        }

        protected string hex_encode(byte[] input)
        {
            string hex = "";
            foreach (byte c in input)
            {
                hex += String.Format("{0:x2}", c);
            }
            return hex;
        }

        private void reportSuccess(string functionName, bool success)
        {
            string statusText;
            if (success)
            {
                this.passedTests++;
                statusText = "OK";

            }
            else
            {
                this.failedTests++;
                statusText = "FAILED";
            }
            this.reportStatus(functionName, statusText);
        }

        private void reportStatusNotImplemented(string functionName)
        {
            this.reportStatus(functionName, "not implemented");
            this.nonImplementedTests++;
        }

        private void reportStatus(string functionName, string status)
        {
            this.completedTests++;

            const int firstColumnWidth = 80;
            string output = functionName + " ";

            for (int i = functionName.Length + 2; i < firstColumnWidth; i++)
            {
                output += ".";
            }

            output += " " + status;

            Console.WriteLine(output);
        }

        private bool AreArraysEqual(IEnumerable<byte> array1, IEnumerable<byte> array2)
        {
            return array1.SequenceEqual(array2);
        }
    }
}
