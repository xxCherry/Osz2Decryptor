namespace Osz2Decryptor.Crypto
{
    public class SimpleCryptor
    {
        private readonly uint[] _key;
        public SimpleCryptor(uint[] key) =>
            _key = key;
        
        public unsafe void EncryptBytes(byte* buf, int length)
        {
            fixed (uint* key = _key)
            {
                var byteKey = (byte*) key;
                var prevEncrypted = (byte)0;
                for (var i = 0; i < length; i++)
                {
                    buf[i] = unchecked ((byte) ((buf[i] + (byteKey[i%16] >> 2))%256));
                    buf[i] ^= RotateLeft(byteKey[15 - i%16], (byte)((prevEncrypted + length - i) % 7));
                    buf[i] = RotateRight(buf[i], (byte)(~(uint)prevEncrypted % 7));

                    prevEncrypted = buf[i];
                }
            }
        }

        public unsafe void DecryptBytes(byte* buf, int length)
        {
            fixed (uint* keyI = _key)
            {
                var byteKey = (byte*) keyI;
                var prevEncrypted = 0;
                for (var i = 0; i < length; i++)
                {
                    var tmpE = buf[i];
                    buf[i] = RotateLeft(buf[i], (byte)((~(uint)(prevEncrypted)) % 7));
                    buf[i]^= RotateLeft(byteKey[15 - i%16], (byte) ((prevEncrypted + length - i)%7));
                    buf[i] = unchecked((byte) ((buf[i] - (byteKey[i%16] >> 2))%256));

                    prevEncrypted = tmpE;
                }
            }
        }

        private static byte RotateLeft(byte val, byte n)
        {
            return (byte) ((val << n) | (val >> (8 - n)));
        }

        private static byte RotateRight(byte val, byte n)
        {
            return (byte)((val >> n) | (val << (8 - n)));
        }
    }
}