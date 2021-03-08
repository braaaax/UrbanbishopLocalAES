using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;

namespace encryptPIC
{
    class Program
    {

        // Display the byte array in a readable format.
        public static void PrintByteArray(byte[] array)
        {
            Console.Write("byte[] OG_hash = { \n");
            for (int i = 0; i < array.Length; i++)

            {
                int n = i + 1;
                if (i == array.Length - 1)
                {
                    Console.Write($"0x{array[i]:X2} \n}};");
                    break;
                }
                Console.Write($"0x{array[i]:X2}, ");
                // if (i == 0) continue;
                if ((n % 16) == 0) Console.Write("\n");
            }
            Console.WriteLine();
        }

        public static void PrintByteEncArray(byte[] array, int encLen)
        {
            Console.Write("byte[] OG_hash = { \n");
            for (int i = 0; i < encLen; i++)

            {
                int n = i + 1;
                if (i == encLen - 1)
                {
                    Console.Write($"0x{array[i]:X2} \n}};");
                    break;
                }
                Console.Write($"0x{array[i]:X2}, ");
                // if (i == 0) continue;
                if ((n % 16) == 0) Console.Write("\n");
            }
            Console.WriteLine();
        }

        public static byte[] EncryptAES(byte[] buffer, byte[] key, byte[] iv, string outfile)
        {
            HashAlgorithm sha = SHA256.Create();
            byte[] result = sha.ComputeHash(buffer);
            Console.Write("[+] SHA256 hash: ");
            PrintByteArray(result);
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (FileStream fs = new FileStream(outfile, FileMode.Create, FileAccess.Write))
                    {
                        using (CryptoStream cs = new CryptoStream(fs, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(buffer, 0, buffer.Length);
                            Console.WriteLine("[+] Len: " + buffer.Length);
                            cs.FlushFinalBlock();
                            Console.WriteLine("[+] wrote " + outfile);
                            return result;
                        }
                    }
                }
            }
        }

        public static byte[] DecryptAES(byte[] buffer, byte[] key, byte[] iv, byte[] OGhash, int origLen)
        {
            if (buffer == null || buffer.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (iv == null || key.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] test = new byte[origLen];
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(buffer))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        csDecrypt.Read(test, 0, origLen);
                        HashAlgorithm sha = SHA256.Create();
                        byte[] result = sha.ComputeHash(test, 0, origLen);
                        bool bEqual = false;
                        if (result.Length == OGhash.Length)
                        {
                            int i = 0;
                            while ((i < result.Length) && (result[i] == OGhash[i]))
                            {
                                i += 1;
                            }
                            if (i == result.Length)
                            {
                                bEqual = true;
                            }
                        }
                        if (bEqual)
                            return test;
                        else
                            return null;
                    }
                }
            }
        }

        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: app.exe infile.bin outfile.bin");
                return;
            }
            string infile = args[0];
            string outfile = args[1];
            byte[] buffer = File.ReadAllBytes(infile);
            // TODO: genreate random
            byte[] iv = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
            byte[] key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x01, 0x07e };
            byte[] oghash = EncryptAES(buffer, key, iv, "AES_encrypted_" + outfile);
            string filename = "AES_encrypted_" + outfile;
            byte[] enc = File.ReadAllBytes(filename);
            Console.WriteLine("[+] ENC Len: " + enc.Length);
            // output for Program.cs
            PrintByteArray(enc);
            if (DecryptAES(enc, key, iv, oghash, buffer.Length) != null) // added len var to DecryptAES for hash verification
            {
                Console.WriteLine("[+] Success!!");
            }
            return;
        }
    }
}