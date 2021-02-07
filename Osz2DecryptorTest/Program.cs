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
            var path = "../../../osz2/nekodex - welcome to christmas!.osz2";
            var osz2 = new Osz2Package(path);
            var osuFile = osz2.Files.ToArray()[0];
            
            File.WriteAllBytes($"../../../osz2/{osuFile.Key}-unpacked", osuFile.Value);
            
            Console.ReadKey();
        }
    }
}