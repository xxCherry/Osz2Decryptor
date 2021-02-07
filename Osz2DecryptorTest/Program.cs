using System;
using System.IO;
using System.Linq;
using Osz2Decryptor;

namespace Osz2DecryptorTest
{
    class Program
    {
        static void Main(string[] args)
        {
            string path;

            if (args.Length < 1)
                path = "..\\..\\..\\osz2\\864877.osz2";
            else
                path = args[0];

            Console.WriteLine($"Decrypting {path}");

            var osz2 = new Osz2Package(path);
            Console.WriteLine("Package read. Unpacked files:");

            var dest = $"{path}-unpacked\\";
            Directory.CreateDirectory(dest);

            foreach (var osuFile in osz2.Files.ToArray())
            {
                Console.WriteLine(osuFile.Key);
                File.WriteAllBytes($"{dest}{osuFile.Key}", osuFile.Value);
            }

            Console.ReadKey();
        }
    }
}