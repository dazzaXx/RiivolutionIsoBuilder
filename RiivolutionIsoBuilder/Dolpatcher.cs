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
			if(offset < 0x80004000)
			{
				Console.WriteLine("WARNING: This patch is being applied to 0x" + offset.ToString("X8") + ", which can break compatibility with USB Loaders.");
			}

			uint dolOffs = getOffsetFromPointer(offset);
			if (dolOffs == 0) //Out of dol range
			{
				// Check whether the patch range [offset, offset+value.Length) extends into an
				// existing DOL section.  If it does, creating a single new section for the
				// entire patch would produce overlapping sections in memory, which causes
				// undefined (often broken) behaviour when the DOL is loaded.  Instead, split
				// the patch at the first existing-section boundary found within the range.
				uint patchEnd = offset + (uint)value.Length;
				uint nearestSectionStart = uint.MaxValue;

				for (int si = 0; si < realPointers.Count; si++)
				{
					if (sectionSizes[si] == 0 || dolOffsets[si] == 0) continue;
					// Find existing sections whose start address falls strictly inside the patch range.
					if (realPointers[si] > offset && realPointers[si] < patchEnd)
					{
						if (realPointers[si] < nearestSectionStart)
							nearestSectionStart = realPointers[si];
					}
				}

				if (nearestSectionStart != uint.MaxValue)
				{
					// The patch straddles a section boundary.  Apply each sub-range separately:
					//   - bytes before the existing section  → create a new section
					//   - bytes from the existing section onward → re-enter doMemoryPatch so
					//     they are applied in-place (or split further if needed)
					int splitPoint = (int)(nearestSectionStart - offset);
					byte[] partOutside = value.Take(splitPoint).ToArray();
					byte[] partInside = value.Skip(splitPoint).ToArray();

					bool success = true;
					if (partOutside.Length > 0)
						success &= createNewSection(offset, partOutside);
					if (partInside.Length > 0)
						success &= doMemoryPatch(nearestSectionStart, partInside, new byte[0]);
					return success;
				}

				return createNewSection(offset, value);
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
					// Determine how many bytes of this patch still fit inside the current section.
					// Find the section that owns dolOffs and compute its remaining capacity.
					uint sectionRemaining = uint.MaxValue;
					for (int si = 0; si < dolOffsets.Count; si++)
					{
						if (dolOffsets[si] == 0 || sectionSizes[si] == 0) continue;
						uint sectionFileEnd = dolOffsets[si] + sectionSizes[si];
						if (dolOffs >= dolOffsets[si] && dolOffs < sectionFileEnd)
						{
							sectionRemaining = sectionFileEnd - dolOffs;
							break;
						}
					}

					// sectionRemaining should always be found since getOffsetFromPointer returned
					// a non-zero value, meaning the address is within a known section.
					// Guard against the unexpected case of dolOffs falling in a gap.
					if (sectionRemaining == uint.MaxValue)
					{
						Console.WriteLine("Patch 0x" + offset.ToString("X8") + ": file offset 0x" + dolOffs.ToString("X") + " is not within any known DOL section.");
						return false;
					}

					int bytesInSection = (int)Math.Min((uint)value.Length, sectionRemaining);

					// Apply the bytes that fit within the current section.
					int j = 0;
					for (int i = (int)dolOffs; i < dolOffs + bytesInSection; i++)
					{
						dol[i] = value[j];
						j++;
					}
					if (!isSilent) Console.WriteLine("Patched " + (bytesInSection == value.Length ? value : value.Take(bytesInSection).ToArray()).AsString() + " at " + offset.ToString("X8") + ((isOriginal) ? (" over " + seq.AsString()) : ""));

					// If the patch extends past this section, apply the remaining bytes as a
					// new patch starting at the next memory address.
					if (bytesInSection < value.Length)
					{
						uint nextOffset = offset + (uint)bytesInSection;
						byte[] remaining = value.Skip(bytesInSection).ToArray();
						if (!isSilent) Console.WriteLine("Patch at 0x" + offset.ToString("X8") + " extends past the end of its DOL section; continuing at 0x" + nextOffset.ToString("X8") + ".");
						return doMemoryPatch(nextOffset, remaining, new byte[0]);
					}

					return true;
				}
				else
				{
					if (!isSilent) Console.WriteLine("Patch " + offset.ToString("X8") + " doesn't answer to original " + original.AsString() + " (has " + seq.AsString() + ") -> Skipping it.");
					return false;
				}
			}
		}

		private bool createNewSection(uint offset, byte[] value)
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

			if (!isSilent) Console.WriteLine("Created new section at 0x" + dolOffsets[newSectionIndex].ToString("X8") + ", pointing at " + offset.ToString("X8") + " (section index: " + newSectionIndex + ").");

			if (mergeSectionsThatCanBeMerged())
			{
				if (!isSilent) Console.WriteLine("Merged sections that could be merged.");
			}

			return true;
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
