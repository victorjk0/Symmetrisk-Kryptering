using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Symmetrisk_Kryptering.Model;

namespace Symmetrisk_Kryptering
{
    class Controller
    {
        Encryptor encryptor = new Encryptor();
        Decryptor decryptor = new Decryptor();
        Stopwatch encWatch = new Stopwatch();
        Stopwatch decWatch = new Stopwatch();

        //Selector function (Menu)
        public List<string> SelectEncryption(string choice, string msg)
        {
            byte[] key;
            byte[] iv;
            byte[] encMsg;
            byte[] decMsg;


            switch (choice)
            {
                //DEC
                //Selects and uses DES encryption
                case "1":
                    key = RandomNumberGenerator(8);
                    iv = RandomNumberGenerator(8);

                    encWatch.Start();
                    encMsg = encryptor.DESEncrypt(msg, key, iv);
                    encWatch.Stop();
                    decWatch.Start();
                    decMsg = decryptor.DESDecrypt(encMsg, key, iv);
                    decWatch.Start();

                    return ReturnStrings(key, iv, encMsg, decMsg, encWatch, decWatch);

                //TripleDES
                //Selects and uses TripleDES encryption
                case "2":
                    key = RandomNumberGenerator(24);
                    iv = RandomNumberGenerator(8);
                    encWatch.Start();
                    encMsg = encryptor.TripleDESEncrypt(msg, key, iv);
                    encWatch.Stop();
                    decWatch.Start();
                    decMsg = decryptor.TripleDESDecrypt(encMsg, key, iv);
                    decWatch.Stop();

                    return ReturnStrings(key, iv, encMsg, decMsg, encWatch, decWatch);

                //AES
                //Selects and uses AES encryption
                case "3":
                    key = RandomNumberGenerator(32);
                    iv = RandomNumberGenerator(16);
                    encWatch.Start();
                    encMsg = encryptor.AESEncrypt(msg, key, iv);
                    encWatch.Stop();
                    decWatch.Start();
                    decMsg = decryptor.AESDecrypt(encMsg, key, iv);
                    decWatch.Start();

                    return ReturnStrings(key, iv, encMsg, decMsg, encWatch, decWatch);

                //Default Nothing Happens.
                default:
                    return null;
            }
        }

        //Generates a random byte array for keys and iv's with a custom size
        public byte[] RandomNumberGenerator(int size)
        {

            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();

            byte[] num = new byte[size];
            
            //Generates the array.
            provider.GetBytes(num);


            return num;
        }


        //Return a List of strings for easy grabble in view
        public List<string> ReturnStrings(byte[] key, byte[] iv, byte[] encMsg, byte[] decMsg, Stopwatch encryptionWatch, Stopwatch decryptionWatch)
        {
            List<string> values = new List<string>();

            values.Add(Convert.ToBase64String(key));
            values.Add(Convert.ToBase64String(iv));
            values.Add(Convert.ToBase64String(encMsg));
            values.Add(Encoding.Default.GetString(decMsg));
            values.Add(encryptionWatch.ElapsedMilliseconds.ToString());
            values.Add(decryptionWatch.ElapsedMilliseconds.ToString());

            return values;
        }



    }
}
