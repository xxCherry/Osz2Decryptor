using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Osz2Decryptor.Enums;
using Osz2Decryptor.IO;
using Osz2Decryptor.Utilities;

namespace Osz2Decryptor
{
    public class Osz2Package
    {
        /// <summary>
        /// A dictionary that contains .osu metadata (e.g Artist, Difficulty, etc..)
        /// </summary>
        public Dictionary<MetaType, string> Metadata = new ();
        
        /// <summary>
        /// A dictionary that contains .osu file info (e.g FileName, Hash, Size etc..)
        /// </summary>
        public Dictionary<string, FileInfo> FileInfos = new ();
        
        /// <summary>
        /// A dictionary that contains osz2 file contents
        /// </summary>
        public Dictionary<string, byte[]> Files = new ();

        /// <summary>
        /// The MD5 hash of 'Metadata' section 
        /// </summary>
        private byte[] _metaDataHash;

        /// <summary>
        /// The MD5 hash of 'FileInfo'
        /// </summary>
        private byte[] _fileInfoHash;

        /// <summary>
        /// The MD5 hash of 'internals' of .osz package
        /// </summary>
        private byte[] _fullBodyHash;

        /// <summary>
        /// The dictionary to get beatmap id by filename
        /// </summary>
        public Dictionary<string, int> FileNames = new ();

        /// <summary>
        /// The dictionary to get filename by beatmap id
        /// </summary>
        public Dictionary<int, string> FileIds = new ();
        
        /// <summary>
        /// Key for XTEA and AES algorithms
        /// </summary>
        private byte[] _key;

        /// <summary>
        /// Need decrypt only metadata?
        /// If false, then it'll decrypt files too.
        /// </summary>
        private bool _metadataOnly;
        
        /// <summary>
        /// Constructor to initialize Osz2Package
        /// </summary>
        /// <param name="path">Path to osz2 file</param>
        public Osz2Package(string path, bool metadataOnly = false)
        {
            _metadataOnly = metadataOnly;
            
            Read(File.OpenRead(path));
        }

        /// <summary>
        /// Reads the metadata of .osu files that osz2 contains
        /// </summary>
        private void Read(Stream file)
        {
            var reader = new BinaryReader(file);

            // identifier aka magic number
            // we use this to check if file
            // that we reading is actually osz2 package
            var identifier = reader.ReadBytes(3);

            // Check if given .osz2 package is valid
            if (identifier.Length < 3 ||
                identifier[0] != 0xEC || // magic number #1
                identifier[1] != 0x48 || // magic number #2
                identifier[2] != 0x4F)   // magic number #3
                throw new("File is not valid .osz2 package");
            
            // Unused. Version, always zero
            reader.ReadByte();
            
            // Unused. IV
            reader.ReadBytes(16); 

            // Read hashes of .osu parts
            _metaDataHash = reader.ReadBytes(16);
            _fileInfoHash = reader.ReadBytes(16);
            _fullBodyHash = reader.ReadBytes(16);

            // Metadata block
            using (var ms = new MemoryStream())
            {
                // Write stuff to compare later
                using (var writer = new BinaryWriter(ms))
                {
                    var count = reader.ReadInt32(); // Count of metadata items
                    writer.Write(count);

                    // Read metadata
                    for (var i = 0; i < count; i++)
                    {
                        var metaType = reader.ReadInt16();
                        var metaValue = reader.ReadString();

                        // Check if value we read is exist in 'MetaType' enum
                        if (Enum.IsDefined(typeof(MetaType), (int) metaType))
                            Metadata.Add((MetaType) metaType, metaValue);

                        writer.Write(metaType);
                        writer.Write(metaValue);
                    }

                    var hash = ComputeOszHash(ms.ToArray(), count * 3, 0xa7);
                    
                    // Check if read metadata hash is equal to computed hash
                    if (!hash.SequenceEqual(_metaDataHash))
                        throw new("Metadata hash mismatch.");
                }
            }

            // Count of maps in .osz2
            var mapsCount = reader.ReadInt32();
            
            // Go through all maps in .osz2 and add them to dictionary
            for (var i = 0; i < mapsCount; i++)
            {
                var fileName = reader.ReadString();
                var beatmapId = reader.ReadInt32();
                
                FileNames.Add(fileName, beatmapId);
                FileIds.Add(beatmapId, fileName);
            }

            // Generate seed using metadata
            var seed = Metadata[MetaType.Creator] +
                       "yhxyfjo5" +
                       Metadata[MetaType.BeatmapSetId];

            // Compute and save key to use in XTEA and AES algorithms
            _key = CryptoUtilities.ComputeHashBytes(seed);

            if (!_metadataOnly)
                ReadFiles(reader);
        }

        /// <summary>
        /// Reads files that packed into .osz2 package
        /// </summary>
        private void ReadFiles(BinaryReader reader)
        {
            using (var decryptor = new XTeaStream(reader.BaseStream, _key))
            {
                var plain = new byte[64];
                decryptor.Read(plain, 0, 64); // magic encrypted bytes

                // TODO: compare magic bytes??
            }

            // Read encrypted length
            var length = reader.ReadInt32();

            // Decode length by encrypted length
            for (var i = 0; i < 16; i += 2)
                length -= _fileInfoHash[i] | (_fileInfoHash[i + 1] << 17);

            // Read all .osu files in .osz2
            var fileInfo = reader.ReadBytes(length);

            // File start offset
            var fileOffset = (int) reader.BaseStream.Position;
            
            using (var ms = new MemoryStream(fileInfo))
            {
                using (var xxTeaStream = new XXTeaStream(ms, _key))
                {
                    using (var fileReader = new BinaryReader(xxTeaStream))
                    {
                        var count = fileReader.ReadInt32();

                        // Compute hash of file info
                        var hash = ComputeOszHash(fileInfo, count * 4, 0xd1);

                        // Check if read FileInfo hash equal to computed hash
                        if (!hash.SequenceEqual(_fileInfoHash))
                            throw new("FileInfo hash mismatch."); 

                        var currentOffset = fileReader.ReadInt32();

                        for (var i = 0; i < count; i++)
                        {
                            // .osu file name
                            var fileName = fileReader.ReadString();

                            // .osu file hash
                            var fileHash = fileReader.ReadBytes(16);

                            var fileDateCreated = DateTime.FromBinary(fileReader.ReadInt64());
                            var fileDateModified = DateTime.FromBinary(fileReader.ReadInt64());

                            var nextOffset = 0;

                            if (i + 1 < count)
                                nextOffset = fileReader.ReadInt32();
                            else
                                nextOffset = (int) reader.BaseStream.Length - fileOffset;

                            var fileLength = nextOffset - currentOffset;

                            FileInfos.Add(fileName,  new(fileName, currentOffset, fileLength, fileHash, fileDateCreated, fileDateModified));

                            currentOffset = nextOffset;
                        }
                    }

                    // Read file contents by info we got above
                    foreach (var (key, value) in FileInfos)
                    {
                        using var osz2Stream = new Osz2Stream(reader.BaseStream, fileOffset + value.Offset, _key);
                        using var osz2Reader = new BinaryReader(osz2Stream);

                        try
                        {
                            Files.Add(key, osz2Reader.ReadBytes(value.Size - 4));
                        }
                        catch
                        {
                            Console.WriteLine("Failed to read: " + key);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Compute MD5 hash of .osz parts
        /// </summary>
        /// <param name="buffer">The buffer to compute</param>
        /// <param name="pos">Position to swap bit at</param>
        /// <param name="swap">Xor byte</param>
        /// <returns>The computed hash</returns>
        private static IEnumerable<byte> ComputeOszHash(byte[] buffer, int pos, byte swap)
        {
            buffer[pos] ^= swap;
            var hash = CryptoUtilities.ComputeHashBytes(buffer);
            buffer[pos] ^= swap;

            for (var i = 0; i < 8; i++)
            {
                var tmp = hash[i];
                hash[i] = hash[i + 8];
                hash[i + 8] = tmp;
            }

            hash[5] ^= 0x2d;
            return hash;
        }
        
        /// <summary>
        /// Checks if given filename is video file
        /// </summary>
        /// <param name="name">Path to file or file name</param>
        /// <returns>True if file is Video and False if not</returns>
        private static bool IsVideo(string name)
        {
            var extension = Path.GetExtension(name);
            switch (extension)
            {
                case ".avi":
                case ".flv":
                case ".mpg":
                case ".wmv":
                case ".m4v":
                case ".mp4":
                    return true;
                default:
                    return false;
            }
        }
    }
}
