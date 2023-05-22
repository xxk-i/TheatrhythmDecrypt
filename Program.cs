using System.Security.Cryptography;

namespace TheatrhythmDecrypt {
    internal class Program {
        static void Main(string[] args)
        {
            byte[] magic = { 0x55, 0x6e, 0x69, 0x74 };
            var fp = CHANGE ME;
            foreach (var file in Directory.GetFiles(fp))
            {
                var f = new FileInfo(file);

                var encrypted = ReadAll(f);
                
                //if (encrypted[..4].SequenceEqual(magic))
                //{
                //    continue;
                //}

                var password = getEncryptionKey();

                var aes = new RijndaelManaged();
                var stream = new MemoryStream(encrypted, true);
                readAESParameter(stream, out var salt, out var iv);
                setupAES(aes, password, salt, iv);

                byte[] decrypted;
                using (var decrypt = aes.CreateDecryptor())
                {
                    try
                    {
                        decrypted = decrypt.TransformFinalBlock(encrypted, 0x20, encrypted.Length - 0x20);
                    }

                    catch (Exception ex)
                    {
                        continue;
                    }
                }

                //var of = f.FullName;
                //of = of.Substring(0, of.Length - f.Extension.Length - 1);

                if (decrypted[..4].SequenceEqual(magic))
                {
                    var ofi = new FileInfo(f.DirectoryName + "/decrypted/ " + f.Name.Substring(0, f.Name.Length - f.Extension.Length - 1) + ".dec" + f.Extension);
                    WriteAll(ofi, decrypted);

                }
            }
        }

        static string DecryptKey(string base64)
        {
            var encryptionKey = Convert.FromBase64String(base64);
            var encryptionKeyAsUShorts = new ushort[encryptionKey.Length / 2];
            for (var i = 0; i < encryptionKey.Length; i += 2) {
                encryptionKeyAsUShorts[i / 2] = (ushort)((encryptionKey[i] << 8) | encryptionKey[i + 1]);
            }

            var key = new char[encryptionKeyAsUShorts.Length / 2];

            uint seed = Constants.xorSeed;
            var inputOffset = 0;
            for (var i = key.Length - 1; i >= 0; i--) {
                var low = encryptionKeyAsUShorts[inputOffset];
                var high = encryptionKeyAsUShorts[inputOffset + 1];
                inputOffset += 2;

                var val = high ^ seed ^ low;
                key[i] = Convert.ToChar(val);

                seed = (val >> 8) & 0xF;
            }

            return new string(key);
        }

        static string getEncryptionKey()
        {
            var key = DecryptKey(Constants.encryptedEncryptionKey);
            return key.Substring(2, key.Length-4);
        }

        static void readAESParameter(MemoryStream stream, out byte[] salt, out byte[] iv)
        {
            salt = new byte[0x10];
            iv = new byte[0x10];

            stream.Read(salt, 0, 8);
            stream.Read(iv, 8, 8);
            stream.Read(iv, 0, 8);
            stream.Read(salt, 8, 8);
        }

        static void setupAES(RijndaelManaged aes, string password, byte[] salt, byte[] iv)
        {
            var derive = new Rfc2898DeriveBytes(password, salt);
            aes.BlockSize = 128;
            aes.KeySize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = derive.GetBytes(16);
            aes.IV = iv;
        }

        static byte[] ReadAll(FileInfo fi)
        {
            using var s = fi.OpenRead();
            var b = new byte[s.Length];
            s.Read(b);
            return b;
        }

        static void WriteAll(FileInfo fi, byte[] data) {
            using var s = fi.Create();
            s.Write(data);
        }
    }
}