using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Symmetrisk_Kryptering.Model
{
    class Encryptor
    {

        //Encryptor For DES
        public byte[] DESEncrypt(string message, byte[] key, byte[] iv)
        {
            DES des = new DESCryptoServiceProvider();
            MemoryStream memStream = new MemoryStream();

            //Sets the Initiallization vector with our random number
            des.IV = iv;

            //Sets the Encryption key with our random number
            des.Key = key;

            //Runs our message through a XOR gate with our iv. before its Encrypted
            des.Mode = CipherMode.CBC;

            //Fills the rest of the block with random data.
            des.Padding = PaddingMode.ISO10126;

            //Converting our Text message to a byte array
            byte[] baMsg = Encoding.UTF8.GetBytes(message);

            //inits the CryptoStream with the Encrypting function and write mode.
            CryptoStream cryptoStream = new CryptoStream(memStream, des.CreateEncryptor(), CryptoStreamMode.Write);
            
            //Encrypts our plaintext message from the beginning
            cryptoStream.Write(baMsg, 0, baMsg.Length);

            //Closes and flushes buffer.
            cryptoStream.Close();

            return memStream.ToArray();
        }

        //Encryptor For TripleDES
        public byte[] TripleDESEncrypt(string message, byte[] key, byte[] iv)
        {
            TripleDES tripleDes = new TripleDESCryptoServiceProvider();
            MemoryStream memStream = new MemoryStream();

            //Sets the Initiallization vector with our random number
            tripleDes.IV = iv;

            //Sets the Encryption key with our random number
            tripleDes.Key = key;

            //Runs our message through a XOR gate with our iv. before its Encrypted
            tripleDes.Mode = CipherMode.CBC;

            //Fills the rest of the block with random data.
            tripleDes.Padding = PaddingMode.ISO10126;

            //Converting our Text message to a byte array
            byte[] baMsg = Encoding.UTF8.GetBytes(message);

            //inits the CryptoStream with the Encrypting function and write mode.
            CryptoStream cryptoStream = new CryptoStream(memStream, tripleDes.CreateEncryptor(), CryptoStreamMode.Write);

            //Encrypts our plaintext message from the beginning
            cryptoStream.Write(baMsg, 0, baMsg.Length);

            //Closes and flushes buffer.
            cryptoStream.Close();

            return memStream.ToArray();
        }

        //Encryptor For AES
        public byte[] AESEncrypt(string message, byte[] key, byte[] iv)
        {
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            MemoryStream memStream = new MemoryStream();

            //Sets the Initiallization vector with our random number
            aes.IV = iv;

            //Sets the Encryption key with our random number
            aes.Key = key;

            //Runs our message through a XOR gate with our iv. before its Encrypted
            aes.Mode = CipherMode.CBC;

            //Fills the rest of the block with random data.
            aes.Padding = PaddingMode.ISO10126;

            //Converting our Text message to a byte array
            byte[] baMsg = Encoding.UTF8.GetBytes(message);

            //inits the CryptoStream with the Encrypting function and write mode.
            CryptoStream cryptoStream = new CryptoStream(memStream, aes.CreateEncryptor(), CryptoStreamMode.Write);

            //Encrypts our plaintext message from the beginning
            cryptoStream.Write(baMsg, 0, baMsg.Length);

            //Closes and flushes buffer.
            cryptoStream.Close();

            return memStream.ToArray();
        }
    }
}
