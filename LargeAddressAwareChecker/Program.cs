/**
 * Copyright (C) 2014 Oleg Chirukhin
 * Licensed under the Apache License 2.0, 
 * see LICENSE-2.0.txt, LICENSE (it's a copy of LICENSE-2.0.txt) and NOTICE for additional information.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LargeAddressAwareChecker
{
    class Program
    {
        const int IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x20;


        //This article help a lot: http://stackoverflow.com/questions/9054469/how-to-check-if-exe-is-set-as-largeaddressaware
        static bool LargeAware(Stream stream)
        {

            var br = new BinaryReader(stream);
            var bw = new BinaryWriter(stream);

            if (br.ReadInt16() != 0x5A4D)       //No MZ Header
                return false;

            br.BaseStream.Position = 0x3C;
            var peloc = br.ReadInt32();         //Get the PE header location.

            br.BaseStream.Position = peloc;
            if (br.ReadInt32() != 0x4550)       //No PE header
                return false;

            br.BaseStream.Position += 0x12;
            long nFilePos = (int)br.BaseStream.Position;
            Int16 nLgaInt = br.ReadInt16();
            bool bIsLGA = (nLgaInt & IMAGE_FILE_LARGE_ADDRESS_AWARE) == IMAGE_FILE_LARGE_ADDRESS_AWARE;
            if (bIsLGA)
                return true;
            nLgaInt |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
            long nFilePos1 = bw.Seek((int)nFilePos, SeekOrigin.Begin);
            bw.Write(nLgaInt);
            bw.Flush();
            long nFilePos2 = br.BaseStream.Seek(nFilePos, SeekOrigin.Begin);
            nLgaInt = br.ReadInt16();
            bIsLGA = (nLgaInt & IMAGE_FILE_LARGE_ADDRESS_AWARE) == IMAGE_FILE_LARGE_ADDRESS_AWARE;
            return bIsLGA;
        }

        static bool LargeAware(string file)
        {
            using (var fs = File.Open(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                bool b = LargeAware(fs);
                fs.Close();
                return b;
            }
        }

        static void Main(string[] args)
        {
            bool isAware = false;

            if (args.Any())
            {
                var path = args[0];
                if (File.Exists(path))
                {
                    isAware = LargeAware(path);
                    if (isAware)
                    {
                        Console.WriteLine("LARGEADDRESSAWARE ON");
                    }
                    else
                    {
                        Console.WriteLine("LARGEADDRESSAWARE OFF");
                    }
                }
                else
                {
                    Console.WriteLine("File does not exist");
                }

            }
            else
            {
                Console.WriteLine("Usage:\nLargeAddressAwareChecker.exe path\nand path should be full absolute path to your exe file");
            }            
                        
        }

    }
}
