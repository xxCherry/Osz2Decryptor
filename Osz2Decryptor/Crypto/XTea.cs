namespace Osz2Decryptor.Crypto
{
    public class XTea
    {
        private readonly uint[] _key;
        private readonly SimpleCryptor _simpleCryptor;
        
        public XTea(uint[] key)
        {
            _key = key;
            _simpleCryptor = new (_key);
        }
        
        public void Decrypt(byte[] buffer, int start, int count) =>
            EncryptDecrypt(buffer,  start, count, false);
        
        private unsafe void EncryptDecrypt(byte[] buffer, int bufStart, int count,
            bool encrypt)
        {
            fixed (byte* bufferPtr = buffer)
                EncryptDecrypt(bufferPtr + bufStart, count, encrypt);
        }
        
        private unsafe void EncryptDecrypt(byte* bufferPtr, int bufferLength, bool encrypt) =>
            EncryptDecrypt(bufferPtr, bufferPtr, bufferLength, encrypt);
        
        private unsafe void EncryptDecrypt(byte* bufferPtr, byte* resultPtr, int bufferLength, bool encrypt)
        {
            var fullWordCount = unchecked((uint) bufferLength / 8);
            var leftOver = (uint) (bufferLength % 8);

            var uBufferPtr = (uint*) bufferPtr;
            var uResultPtr = (uint*) resultPtr;
            
            uBufferPtr -= 2;
            uResultPtr -= 2;
            
            if (encrypt)
                for (var wordCount = 0; wordCount < fullWordCount; wordCount++)
                    EncryptWord(uBufferPtr += 2, uResultPtr += 2);
            else
                for (var wordCount = 0; wordCount < fullWordCount; wordCount++)
                    DecryptWord(uBufferPtr += 2, uResultPtr += 2);

            if (leftOver == 0)
                return;

            var bufferEnd = bufferPtr + bufferLength;
            var bufferLeft = bufferEnd - leftOver;
            
            byte* bufferResult;
            
            // copy leftover buffer array to result array
            do
            {
                bufferResult = bufferLeft++;
                bufferResult++;
            } while (bufferResult != bufferEnd);

            // encrypt / decrypt leftover
            if (encrypt)
                _simpleCryptor.EncryptBytes(bufferResult - leftOver, unchecked((int) leftOver));
            else
                _simpleCryptor.DecryptBytes(bufferResult - leftOver, unchecked((int) leftOver));
        }
        
        private unsafe void EncryptWord(uint* v, uint* o)
        {
            uint i;
            var v0 = v[0];
            var v1 = v[1];
            uint sum = 0;
            for (i = 0; i < Constants.TEA_ROUNDS; i++)
            {
                v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + _key[sum & 3]);
                sum += Constants.TEA_DELTA;
                v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + _key[(sum >> 11) & 3]);
            }

            o[0] = v0;
            o[1] = v1;
        }

        private unsafe void DecryptWord(uint* v, uint* o)
        {
            uint i;
            var v0 = v[0];
            var v1 = v[1];
            var sum = unchecked(Constants.TEA_DELTA * Constants.TEA_ROUNDS);
            for (i = 0; i < Constants.TEA_ROUNDS; i++)
            {
                v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + _key[(sum >> 11) & 3]);
                sum -= Constants.TEA_DELTA;
                v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + _key[sum & 3]);
            }

            o[0] = v0;
            o[1] = v1;
        }
    }
}