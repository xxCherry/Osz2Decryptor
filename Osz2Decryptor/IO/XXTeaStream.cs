using System;
using System.IO;
using Osz2Decryptor.Crypto;

namespace Osz2Decryptor.IO
{
    public class XXTeaStream : Stream
    {
        public override bool CanRead => _internalStream.CanRead;

        public override bool CanSeek => _internalStream.CanSeek;

        public override bool CanWrite => _internalStream.CanWrite;

        public override long Length => _internalStream.Length;

        public override long Position
        {
            get => _internalStream.Position;
            set => _internalStream.Position = value;
        }

        /// <summary>
        /// Internal stream
        /// </summary>
        private readonly Stream _internalStream;

        /// <summary>
        /// XXTea provider
        /// </summary>
        private readonly XXTea _xxtea;

        public unsafe XXTeaStream(Stream stream, byte[] key)
        {
            _internalStream = stream;

            var keyBuffer = new uint[4];
            fixed (byte* ptr = key)
            {
                fixed (uint* keyPtr = keyBuffer)
                {
                    var tmp = (uint*)ptr;
                    *keyPtr = *tmp;
                    keyPtr[1] = tmp[1];
                    keyPtr[2] = tmp[2];
                    keyPtr[3] = tmp[3];
                }
            }
            
            _xxtea = new(keyBuffer);
        }

        /// <summary>
        /// Decrypt using XXTea algorithm
        /// </summary>
        /// <param name="buffer">Buffer to decrypt</param>
        /// <param name="start">Start decrypt from (offset)</param>
        /// <param name="count">Count of bytes to decrypt</param>
        private void Decrypt(byte[] buffer, int start, int count)
        {
            _xxtea.Decrypt(buffer, start, count);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var bytesRead = _internalStream.Read(buffer, offset, count);
            Decrypt(buffer, offset, count);
            
            return bytesRead;
        }
        
        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }
}