using ExtensionMethods;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RiivolutionIsoBuilder
{
    class Dolpatcher
    {
        List<uint> dolOffsets = new List<uint>();
        List<uint> realPointers = new List<uint>();
        List<uint> sectionSizes = new List<uint>();
        byte[] dol = new byte[0];

		List<int> newSectionsIndexes = new List<int>();

		string dolPath = "";
		bool isSilent;

		uint originalEntryPoint;
		List<(uint addr, byte[] value)> pendingLowMemPatches = new List<(uint, byte[])>();


		public Dolpatcher(string dolPath, bool isSilent)
        {
            dol = System.IO.File.ReadAllBytes(dolPath);
            Console.WriteLine("Decoding DOL file header...");

            for (int i = 0; i < 0x48; i += 4)
            {
                dolOffsets.Add(BitConverter.ToUInt32(dol.Skip(i).Take(4).Reverse().ToArray(), 0));
                realPointers.Add(BitConverter.ToUInt32(dol.Skip(i + 0x48).Take(4).Reverse().ToArray(), 0));
                sectionSizes.Add(BitConverter.ToUInt32(dol.Skip(i + 0x90).Take(4).Reverse().ToArray(), 0));
            }

			originalEntryPoint = BitConverter.ToUInt32(dol.Skip(0xE0).Take(4).Reverse().ToArray(), 0);

			this.dolPath = dolPath;
			this.isSilent = isSilent;
		}

		public void saveDol()
		{
			reencodeDolHeader();
			System.IO.File.WriteAllBytes(dolPath, dol);
		}

        public bool doMemoryPatch(uint offset, byte[] value, byte[] original)
        {
			if (offset < 0x80004000)
			{
				if (!isSilent) Console.WriteLine("Queuing low-memory patch at 0x" + offset.ToString("X8") + " for middleman injection.");
				pendingLowMemPatches.Add((offset, value));
				return true;
			}

			uint dolOffs = getOffsetFromPointer(offset);
			if (dolOffs == 0) //Out of dol range
			{
				int newSectionIndex = getNextEmptySection();

				if (newSectionIndex < 0)
				{
					Console.WriteLine("Can't create a new section for pointer 0x" + offset.ToString("X8") + ": No free section available.");
					return false;
				}

				int highestSection = getHighestSection();

				byte[] previousSections = dol.Take((int)(dolOffsets[highestSection] + sectionSizes[highestSection])).ToArray();
				byte[] footer = dol.Skip((int)(dolOffsets[highestSection] + sectionSizes[highestSection])).ToArray();
				dol = previousSections.Concat(value).Concat(footer).ToArray();
				dolOffsets[newSectionIndex] = dolOffsets[highestSection] + sectionSizes[highestSection];
				realPointers[newSectionIndex] = offset;
				sectionSizes[newSectionIndex] = (uint)value.Length;

				for (int i = 0; i < 4; i++)
				{
					dol[4 * newSectionIndex + i] = Convert.ToByte(dolOffsets[newSectionIndex].ToString("X8").Substring(i * 2, 2), 16);
					dol[4 * newSectionIndex + i + 0x48] = Convert.ToByte(realPointers[newSectionIndex].ToString("X8").Substring(i * 2, 2), 16);
					dol[4 * newSectionIndex + i + 0x90] = Convert.ToByte(sectionSizes[newSectionIndex].ToString("X8").Substring(i * 2, 2), 16);
				}

				newSectionsIndexes.Add(newSectionIndex);

				dolOffs = getOffsetFromPointer(offset);

				if (!isSilent) Console.WriteLine("Created new section at 0x" + dolOffs.ToString("X") + ", pointing at " + offset.ToString("X8") + " (section index: " + newSectionIndex + ").");

				if (mergeSectionsThatCanBeMerged())
				{
					if (!isSilent) Console.WriteLine("Merged sections that could be merged.");
				}

				return true;
			}
			else
			{
				bool isOriginal = original.Length > 0;

				List<byte> seq = new List<byte>();
				for (int i = (int)dolOffs; i < dolOffs + original.Length; i++)
				{
					seq.Add(dol[i]);
				}
				if ((isOriginal && seq.ToArray().SequenceEqual(original)) || !isOriginal)
				{
					try
					{
						int j = 0;
						for (int i = (int)dolOffs; i < dolOffs + value.Length; i++)
						{
							dol[i] = value[j];
							j++;
						}
						if (!isSilent) Console.WriteLine("Patched " + value.AsString() + " at " + offset.ToString("X8") + ((isOriginal) ? (" over " + seq.AsString()) : ""));

						return true;
					}
					catch(Exception e)
					{
						Console.WriteLine("Patch " + offset.ToString("X8") + " starts within the DOL range but ends out of it");
						return false;
					}
				}
				else
				{
					if (!isSilent) Console.WriteLine("Patch " + offset.ToString("X8") + " doesn't answer to original " + original.AsString() + " (has " + seq.AsString() + ") -> Skipping it.");
					return false;
				}
			}
		}

		public uint getOffsetFromPointer(uint pointer)
		{
			for (int i = 0; i < dolOffsets.Count; i++)
			{
				if (pointer >= realPointers[i] && pointer < (realPointers[i] + sectionSizes[i]))
				{
					return dolOffsets[i] + (pointer - realPointers[i]);
				}
			}

			return 0;
		}

		public int getHighestSection()
		{
			int sectionIndex = 0;
			for (int i = 0; i < dolOffsets.Count; i++)
			{
				if (dolOffsets[i] > dolOffsets[sectionIndex])
				{
					sectionIndex = i;
				}
			}
			return sectionIndex;
		}

		public int getNextEmptySection()
		{
			for (int i = 0; i < dolOffsets.Count; i++)
			{
				if (dolOffsets[i] == 0)
				{
					return i;
				}
			}
			return -1;
		}

		public bool mergeSectionsThatCanBeMerged()
		{
			bool didMerged = false;
			foreach (int newSection in newSectionsIndexes)
			{
				foreach (int otherSection in newSectionsIndexes)
				{
					if (otherSection == newSection)
					{
						continue;
					}
					if (realPointers[newSection] + sectionSizes[newSection] == realPointers[otherSection])
					{
						sectionSizes[newSection] += sectionSizes[otherSection];
						dolOffsets[otherSection] = 0;
						realPointers[otherSection] = 0;
						sectionSizes[otherSection] = 0;
						didMerged = true;
					}
				}
			}
			reencodeDolHeader();
			return didMerged;
		}

		public bool buildAndInjectMiddleman()
		{
			if (pendingLowMemPatches.Count == 0)
				return false;

			if (!isSilent) Console.WriteLine("Building middleman DOL section for " + pendingLowMemPatches.Count + " low-memory patch(es)...");

			List<uint> instructions = new List<uint>();

			foreach (var patch in pendingLowMemPatches)
			{
				uint currentAddr = patch.addr;
				byte[] value = patch.value;
				int remaining = value.Length;
				int valueOffset = 0;

				while (remaining >= 4)
				{
					uint wordVal = ((uint)value[valueOffset] << 24) |
					               ((uint)value[valueOffset + 1] << 16) |
					               ((uint)value[valueOffset + 2] << 8) |
					               (uint)value[valueOffset + 3];

					emitLoadAddressAndValue(instructions, currentAddr, wordVal);
					instructions.Add(0x90830000); // stw r4, 0(r3)
					emitCacheFlush(instructions);

					currentAddr += 4;
					valueOffset += 4;
					remaining -= 4;
				}

				if (remaining >= 2)
				{
					uint halfVal = ((uint)value[valueOffset] << 8) | (uint)value[valueOffset + 1];

					emitLoadAddressAndValue(instructions, currentAddr, halfVal);
					instructions.Add(0xB0830000); // sth r4, 0(r3)
					emitCacheFlush(instructions);

					currentAddr += 2;
					valueOffset += 2;
					remaining -= 2;
				}

				if (remaining == 1)
				{
					uint byteVal = (uint)value[valueOffset];

					emitLoadAddressAndValue(instructions, currentAddr, byteVal);
					instructions.Add(0x98830000); // stb r4, 0(r3)
					emitCacheFlush(instructions);
				}
			}

			// Jump to original entry point
			emitLoadR3(instructions, originalEntryPoint);
			instructions.Add(0x7C6903A6);                                           // mtctr r3
			instructions.Add(0x4E800420);                                           // bctr

			// Convert to big-endian byte array
			byte[] middlemanCode = new byte[instructions.Count * 4];
			for (int i = 0; i < instructions.Count; i++)
			{
				middlemanCode[i * 4 + 0] = (byte)((instructions[i] >> 24) & 0xFF);
				middlemanCode[i * 4 + 1] = (byte)((instructions[i] >> 16) & 0xFF);
				middlemanCode[i * 4 + 2] = (byte)((instructions[i] >> 8) & 0xFF);
				middlemanCode[i * 4 + 3] = (byte)(instructions[i] & 0xFF);
			}

			// Get a free section slot
			int newSectionIndex = getNextEmptySection();
			if (newSectionIndex < 0)
			{
				Console.WriteLine("Can't inject middleman: No free DOL section slot available.");
				return false;
			}

			// Find highest section in the file to determine append position
			int highestSection = getHighestSection();
			uint fileEnd = dolOffsets[highestSection] + sectionSizes[highestSection];

			// Find highest virtual address end to determine safe virtual address
			uint newVirtualAddr = getHighestVirtualEnd();
			if (newVirtualAddr < 0x80004000)
				newVirtualAddr = 0x80004000;
			if (newVirtualAddr % 0x20 != 0)
				newVirtualAddr = (newVirtualAddr / 0x20 + 1) * 0x20;

			// Align DOL file offset to 0x20
			uint newDolOffset = fileEnd;
			if (newDolOffset % 0x20 != 0)
				newDolOffset = (newDolOffset / 0x20 + 1) * 0x20;

			// Extend DOL: existing content + alignment padding + middleman code
			int paddingSize = (int)(newDolOffset - fileEnd);
			byte[] previousContent = dol.Take((int)fileEnd).ToArray();
			byte[] footer = dol.Skip((int)fileEnd).ToArray();
			byte[] padding = new byte[paddingSize];

			dol = previousContent.Concat(padding).Concat(middlemanCode).Concat(footer).ToArray();

			dolOffsets[newSectionIndex] = newDolOffset;
			realPointers[newSectionIndex] = newVirtualAddr;
			sectionSizes[newSectionIndex] = (uint)middlemanCode.Length;

			newSectionsIndexes.Add(newSectionIndex);

			reencodeDolHeader();

			// Update entry point to point to middleman
			dol[0xE0] = (byte)((newVirtualAddr >> 24) & 0xFF);
			dol[0xE1] = (byte)((newVirtualAddr >> 16) & 0xFF);
			dol[0xE2] = (byte)((newVirtualAddr >> 8) & 0xFF);
			dol[0xE3] = (byte)(newVirtualAddr & 0xFF);

			if (!isSilent) Console.WriteLine("Middleman injected at virtual address 0x" + newVirtualAddr.ToString("X8") + " (original entry point: 0x" + originalEntryPoint.ToString("X8") + ").");

			if (mergeSectionsThatCanBeMerged())
			{
				if (!isSilent) Console.WriteLine("Merged sections that could be merged.");
			}

			return true;
		}

		private uint getHighestVirtualEnd()
		{
			uint highestEnd = 0;
			for (int i = 0; i < realPointers.Count; i++)
			{
				if (sectionSizes[i] > 0)
				{
					uint end = realPointers[i] + sectionSizes[i];
					if (end > highestEnd)
						highestEnd = end;
				}
			}
			return highestEnd;
		}

		private void emitLoadR3(List<uint> instructions, uint addr)
		{
			instructions.Add(0x3C600000 | ((addr >> 16) & 0xFFFF)); // lis r3, hi(addr)
			instructions.Add(0x60630000 | (addr & 0xFFFF));          // ori r3, r3, lo(addr)
		}

		private void emitLoadAddressAndValue(List<uint> instructions, uint addr, uint val)
		{
			emitLoadR3(instructions, addr);
			instructions.Add(0x3C800000 | ((val >> 16) & 0xFFFF));   // lis r4, hi(val)
			instructions.Add(0x60840000 | (val & 0xFFFF));            // ori r4, r4, lo(val)
		}

		private void emitCacheFlush(List<uint> instructions)
		{
			instructions.Add(0x7C001866); // dcbst 0, r3
			instructions.Add(0x7C0004AC); // sync
			instructions.Add(0x7C001FAC); // icbi 0, r3
			instructions.Add(0x4C00012C); // isync
		}

		public void reencodeDolHeader()
		{
			for (int i = 0; i < dolOffsets.Count; i++)
			{
				for (int j = 0; j < 4; j++)
				{
					dol[4 * i + j] = Convert.ToByte(dolOffsets[i].ToString("X8").Substring(j * 2, 2), 16);
					dol[4 * i + j + 0x48] = Convert.ToByte(realPointers[i].ToString("X8").Substring(j * 2, 2), 16);
					dol[4 * i + j + 0x90] = Convert.ToByte(sectionSizes[i].ToString("X8").Substring(j * 2, 2), 16);
				}
			}
		}
	}
}
