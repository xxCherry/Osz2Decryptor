using System;
using System.IO;
using Osz2Decryptor.Crypto;

namespace Osz2Decryptor.IO
{
    public class Osz2Stream : Stream
    {
        public override bool CanRead { get; } = true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => 0;

        public override long Position { 
            get => _position - _offset;
            set => _position = value;
        }

        private readonly int _offset;
        private readonly int _length;
        private long _position;
        
        private readonly byte[] _skipBuffer = new byte[64];
        
        /// <summary>
        /// XXTea provider
        /// </summary>
        private readonly XXTea _xxtea;
        
        /// <summary>
        /// Internal stream
        /// </summary>
        private readonly Stream _internalStream;

        public unsafe Osz2Stream(Stream stream, int offset, byte[] key)
        {
            var encryptedLength = new byte[4];
            
            stream.Seek(offset, SeekOrigin.Begin);
            stream.Read(encryptedLength, 0, 4);
            
            _internalStream = stream;
            _internalStream.Position = _offset = offset + 4;
            
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
            
            Decrypt(encryptedLength, 0, 4);
            
            _length = encryptedLength[0] |
                      encryptedLength[1] << 8 | 
                      encryptedLength[2] << 16 | 
                      encryptedLength[3] << 24;
            
            _position = _offset;
        }

        /// <summary>
        /// Decrypt via XXTea algorithm
        /// </summary>
        /// <param name="buffer">Buffer to decrypt</param>
        /// <param name="start">Start decrypt from (offset)</param>
        /// <param name="count">Count of bytes to decrypt</param>
        private void Decrypt(byte[] buffer, int start, int count) =>
            _xxtea.Decrypt(buffer, start, count);
        
        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (Position + count > _length)
                count = _length - (int) _position;

            if (count == 0)
                return 0;

            var localPosition = _position - _offset;
            var seekablePosition = localPosition & ~0x3FL;
            var skipOffset = (int) localPosition % 64;
            var seekableBytes = count - (64 - skipOffset);

            var endLeftOver = 0;
            var seekableEnd = 0;
            
            // If we're not out of bounds
            if (seekableBytes > 0)
            {
                // Now we can calculate end of buffer?
                seekableEnd = ((int)localPosition + count) & ~0x3F;
                endLeftOver = ((int)localPosition + count) % 64;
                seekableBytes =  seekableEnd - (64 - skipOffset + (int)localPosition);
                
                // If we have data to read
                if (seekableBytes > 0)
                {
                    // Read data and decrypt
                    _internalStream.Position = _position;
                    _internalStream.Read(buffer, offset, count);
                    Decrypt(buffer, 64 - skipOffset + offset, seekableBytes);
                }
            }
            
            var firstBytes = Math.Min(64, _length - (int)seekablePosition);
            
            // Read data and decrypt
            _internalStream.Position = seekablePosition + _offset;
            _internalStream.Read(_skipBuffer, 0, firstBytes);
            Decrypt(_skipBuffer, 0, firstBytes);
            
            Array.Copy(_skipBuffer, skipOffset, buffer, offset, Math.Min(64 - skipOffset, count));

            if (endLeftOver > 0)
            {
                var lastBytes = Math.Min(64, _length - seekableEnd);

                // Read data and decrypt
                _internalStream.Position = seekableEnd + _offset;
                _internalStream.Read(_skipBuffer, 0, lastBytes);
                Decrypt(_skipBuffer, 0, lastBytes);
                
                Array.Copy(_skipBuffer, 0, buffer, count - endLeftOver + offset, endLeftOver);
            }

            _internalStream.Position = _position;
            
            Seek(count, SeekOrigin.Current);
            return count;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            switch (origin)
            {
                case SeekOrigin.Begin:
                {
                    if (offset >= 0)
                        _position = Math.Min(offset, _length) + _offset;
                    break;
                }
                case SeekOrigin.Current:
                {
                    if (Position + offset >= 0)
                        _position = Math.Min(_position + offset - _offset, _length) + _offset;
                    break;
                }
                case SeekOrigin.End:
                {
                    if (_length + offset >= 0)
                        _position = _length + offset + _offset;
                    break;
                }
            }
            _internalStream.Seek(_position, SeekOrigin.Begin);
            
            return Position;
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