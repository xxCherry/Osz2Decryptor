using System.Text;
using System.Security.Cryptography;

namespace Osz2Decryptor.Utilities
{
    public class CryptoUtilities
    {
        public static string ComputeHash(string str) => 
            ComputeHash(Encoding.UTF8.GetBytes(str));

        public static string ComputeHash(byte[] buffer)
        {
            var hash = ComputeHashBytes(buffer);
            var sb = new StringBuilder();

            foreach (var b in hash)
                sb.Append(b.ToString("x2"));

            return sb.ToString();
        }
        
        public static byte[] ComputeHashBytes(string str) => 
            ComputeHashBytes(Encoding.ASCII.GetBytes(str));

        public static byte[] ComputeHashBytes(byte[] buffer)
        {
            var md5 = MD5.Create();
            return md5.ComputeHash(buffer);
        }
    }
}