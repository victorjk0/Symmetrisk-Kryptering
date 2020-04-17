using System;
using System.Collections.Generic;
using Symmetrisk_Kryptering.Enums;

namespace Symmetrisk_Kryptering
{
    class Program
    {
        static void Main(string[] args)
        {
            Controller con = new Controller();

            while (true)
            {
  
                List<string> results = new List<string>();
                int num = 1;

                //Outputs what Algorithms to use and option number
                foreach (object item in Enum.GetValues(typeof(Algorithms)))
                {
                    Console.WriteLine("{0}  {1}", num, item);
                    num++;
                }


                Console.Write("Choose Encryption Method: ");
                string choice = Console.ReadLine();

                //Stores the chosen algorithms name.
                Algorithms algo = (Algorithms)Enum.Parse(typeof(Algorithms), choice);


                Console.Clear();

                //Now for the ui stuff. 
                //What can i say alot of printing lines some user input and some more printing lines.
                Console.WriteLine("Write message to encrypt in {0}", algo);
                Console.WriteLine();
                Console.WriteLine();

                Console.Write("Message: ");
                string msg = Console.ReadLine();

                Console.Clear();
                results = con.SelectEncryption(choice, msg);

                Console.WriteLine("Key: {0}", results[0]);
                Console.WriteLine("IV: {0}", results[1]);
                Console.WriteLine("Message: {0}", msg);
                Console.WriteLine("Encrypted Text: {0}", results[2]);
                Console.WriteLine("Decrypted Text: {0}", results[3]);
                Console.WriteLine("Time for encryption: {0}ms", results[4]);
                Console.WriteLine("Time for decryption: {0}ms", results[5]);

                Console.ReadLine();
                Console.Clear();
            }
        }
    }
}
