using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Symmetrisk_Kryptering.Model
{
    class Decryptor
    {


        //Decryptor for DES Encryptions
        public byte[] DESDecrypt(byte[] encMsg, byte[] key, byte[] iv)
        {

            
            DES des = new DESCryptoServiceProvider();
            MemoryStream memStream = new MemoryStream();

            //Sets the Initiallization vector with our random number
            des.IV = iv;

            //Sets the Encryption key with our random number
            des.Key = key;

            //runs our message through a XOR gate with our iv. before its decrypted
            des.Mode = CipherMode.CBC;

            //Fills the rest of the block with random data.
            des.Padding = PaddingMode.ISO10126;

            //inits the CryptoStream with the Decrypting function and write mode.
            CryptoStream cryptoStream = new CryptoStream(memStream, des.CreateDecryptor(), CryptoStreamMode.Write);

            //Decrypts our encrypted message from the beginning
            cryptoStream.Write(encMsg, 0, encMsg.Length);

            //Closes and flushes buffer.
            cryptoStream.Close();
            return memStream.ToArray();
        }

        //Decryptor for TripleDES Encryptions
        public byte[] TripleDESDecrypt(byte[] encMsg, byte[] key, byte[] iv)
        {
            TripleDES tripleDes = new TripleDESCryptoServiceProvider();
            MemoryStream memStream = new MemoryStream();


            //Sets the Initiallization vector with our random number
            tripleDes.IV = iv;

            //Sets the Encryption key with our random number
            tripleDes.Key = key;

            //runs our message through a XOR gate with our iv. before its decrypted
            tripleDes.Mode = CipherMode.CBC;

            //Fills the rest of the block with random data.
            tripleDes.Padding = PaddingMode.ISO10126;

            //inits the CryptoStream with the Decrypting function and write mode.
            CryptoStream cryptoStream = new CryptoStream(memStream, tripleDes.CreateDecryptor(), CryptoStreamMode.Write);

            //Decrypts our encrypted message from the beginning
            cryptoStream.Write(encMsg, 0, encMsg.Length);

            //Closes and flushes buffer.
            cryptoStream.Close();
            return memStream.ToArray();
        }

        //Decryptor for AES Encryptions
        public byte[] AESDecrypt(byte[] encMsg, byte[] key, byte[] iv)
        {
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            MemoryStream memStream = new MemoryStream();

            //Sets the Initiallization vector with our random number
            aes.IV = iv;

            //Sets the Encryption key with our random number
            aes.Key = key;

            //runs our message through a XOR gate with our iv. before its decrypted
            aes.Mode = CipherMode.CBC;

            //Fills the rest of the block with random data.
            aes.Padding = PaddingMode.ISO10126;

            //inits the CryptoStream with the Decrypting function and write mode.
            CryptoStream cryptoStream = new CryptoStream(memStream, aes.CreateDecryptor(), CryptoStreamMode.Write);

            //Decrypts our encrypted message from the beginning
            cryptoStream.Write(encMsg, 0, encMsg.Length);

            //Closes and flushes buffer.
            cryptoStream.Close();
            return memStream.ToArray();
        }
    }
}
