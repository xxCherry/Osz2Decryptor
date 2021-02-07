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
            var path = "../../../osz2/864877.osz2";
            var osz2 = new Osz2Package(path);
            foreach (var file in osz2.Files)
            {
                Console.WriteLine(file);
            }

            Console.WriteLine(osz2.Files.Count);

            var osuFile = osz2.Files.ToArray()[12];
            
            File.WriteAllBytes($"../../../osz2/{osuFile.Key}-unpacked", osuFile.Value);
            
            Console.ReadKey();
        }
    }
}