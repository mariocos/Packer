#include "packer.h"

// unsigned char shellCode[] = {
//     0xb8, 0x01, 0x00, 0x00, 0x00,
//     0xbf, 0x01, 0x00, 0x00, 0x00,
//     0x48, 0x8b, 0x35, 0x10, 0x00, 0x00, 0x00,
//     0xba, 0x01, 0x00, 0x00, 0x00,
//     0x0f, 0x05,
//     0x48, 0x8b, 0x05, 0x03, 0x00, 0x00, 0x00,
//     0xff, 0xe0,
//     0x61,
//     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
// };

// unsigned char shellCode[] = {
//     0x48, 0xbf, 0xf6, 0xf6, 0xf6, 0xf6, 0xf6, 0xf6,
//     0xf6, 0xf6, 0xbe, 0xf0, 0x00, 0x00, 0x00, 0x48,
//     0xba, 0xf5, 0xf5, 0xf5, 0xf5, 0xf5, 0xf5, 0xf5,
//     0xf5, 0x48, 0x83, 0xfe, 0x00, 0x0f, 0x84, 0x81,
//     0x00, 0x00, 0x00, 0x49, 0x89, 0xd0, 0x4d, 0x31,
//     0xd2, 0x49, 0xf7, 0xc2, 0x07, 0x00, 0x00, 0x00,
//     0x75, 0x2c, 0x4d, 0x89, 0xc1, 0x49, 0xc1, 0xe9,
//     0x0c, 0x4d, 0x31, 0xc8, 0x4d, 0x89, 0xc1, 0x49,
//     0xc1, 0xe1, 0x19, 0x4d, 0x31, 0xc8, 0x4d, 0x89,
//     0xc1, 0x49, 0xc1, 0xe9, 0x1b, 0x4d, 0x31, 0xc8,
//     0x49, 0xb9, 0x1d, 0xdd, 0x6c, 0x4f, 0x91, 0xf4,
//     0x45, 0x25, 0x4d, 0x0f, 0xaf, 0xc1, 0x4c, 0x89,
//     0xd0, 0x48, 0x83, 0xe0, 0x07, 0x48, 0xc1, 0xe0,
//     0x03, 0x48, 0x89, 0xc1, 0x4c, 0x89, 0xc2, 0x48,
//     0xd3, 0xea, 0x42, 0x30, 0x14, 0x17, 0x49, 0xff,
//     0xc2, 0x49, 0x39, 0xf2, 0x75, 0xab, 0xe8, 0x0f,
//     0x00, 0x00, 0x00, 0x2e, 0x2e, 0x2e, 0x2e, 0x57,
//     0x4f, 0x4f, 0x44, 0x59, 0x2e, 0x2e, 0x2e, 0x2e,
//     0x2e, 0x0a, 0x5e, 0xb8, 0x01, 0x00, 0x00, 0x00,
//     0xbf, 0x01, 0x00, 0x00, 0x00, 0xba, 0x0f, 0x00,
//     0x00, 0x00, 0x0f, 0x05, 0xe9, 0xfb, 0xff, 0xff,
//     0xff
// };


size_t	fileSize = 0;

/*

*/
void	setReleventPointers(void* map, t_ptrs* elfPtrs, t_ranges* ranges)
{
	// ELF header
	Elf64_Ehdr* eHdr = map;
	elfPtrs->ehdr = eHdr;

	Elf64_Shdr* sHdrTable = map + eHdr->e_shoff;
	elfPtrs->sHdrTable = sHdrTable;
	char* strTable = map + sHdrTable[eHdr->e_shstrndx].sh_offset;
	ranges->shnum = eHdr->e_shnum;

	for (int i = 0 ; i < ranges->shnum ; i++)
	{
		if (ft_strcmp(".text", &strTable[sHdrTable[i].sh_name]) == 0)
		{
			ranges->textIndex = i;
			ranges->firstSectionInSegment = i;
			break ;
		}
	}
	Elf64_Shdr* textShdr = &sHdrTable[ranges->textIndex];
	elfPtrs->textSectionHdr = textShdr;

	
	//Program headers
	Elf64_Phdr* pHdrTable = map + eHdr->e_phoff;
	elfPtrs->pHdrTable = pHdrTable;

	for (int i = 0 ; i < eHdr->e_phnum ; i++)
	{
		if (pHdrTable[i].p_offset <= textShdr->sh_offset
			&& textShdr->sh_offset + textShdr->sh_size <= pHdrTable[i].p_offset + pHdrTable[i].p_filesz
			&& pHdrTable[i].p_vaddr <= textShdr->sh_addr
			&& textShdr->sh_addr + textShdr->sh_size <= pHdrTable[i].p_vaddr + pHdrTable[i].p_filesz)
		{
			ranges->targetSegment = i;
			break ;
		}
	}
	elfPtrs->targetSegment = &pHdrTable[ranges->targetSegment];
}

/* 
Objective of this function is to get a virtual address and file range for the segment that maps .text
*/
void setSegmentRange(void* map, t_ptrs* elfPtrs, t_ranges* ranges)
{
	ranges->segmentStart = elfPtrs->targetSegment->p_offset;
	ranges->segmentSize = elfPtrs->targetSegment->p_filesz;
	ranges->segmentEnd = elfPtrs->targetSegment->p_offset + elfPtrs->targetSegment->p_filesz;
}


/*
Objective of this function is to set a range from start to end of the sections present in the segment that maps .text
*/
void	setSectionsInSegment(void* map, t_ptrs* elfPtrs, t_ranges* ranges)
{
	Elf64_Shdr* ht = elfPtrs->sHdrTable;

	for (int i = 0; i < ranges->shnum ; i++)
	{
		if (ht[i].sh_offset >= ranges->segmentStart && ht[i].sh_offset + ht[i].sh_size <= ranges->segmentEnd 				/* if section is in segment range */
		&& (i < ranges->firstSectionInSegment || i > ranges->lastSectionInSegment)) 										/* if is border section */
			(i < ranges->firstSectionInSegment) ? (ranges->firstSectionInSegment = i) : (ranges->lastSectionInSegment = i); /* set border value */
	}
}


volatile void guaxini(void)
{
	;
}
/*
This function will find the next section in the file that comes after the .text section
and set ranges->sectionAfterText to its index.
if .text is at the end of the file it will set this value to ranges->textIndex instead.
*/
void	setRangeOfText(void* map, t_ptrs* elfPtrs, t_ranges* ranges)
{
	Elf64_Shdr* ht = elfPtrs->sHdrTable;
	size_t nextSection = ranges->textIndex;

	for (int i = 0; i < ranges->shnum ; i++)
	{
		// printf("offsetsi:%d offset[%ld]\n", i, ht[i].sh_offset);//TODO:REMOVE
		if (nextSection = ranges->textIndex && ht[i].sh_offset > elfPtrs->textSectionHdr->sh_offset)
			nextSection = i;
		else if (ht[i].sh_offset > elfPtrs->textSectionHdr->sh_offset && ht[i].sh_offset < ht[nextSection].sh_offset)
			nextSection = i;
	}
	ranges->sectionAfterText = nextSection;
}

int main(int ac, char** av)
{
	if (ac != 2)
	{
		printf("Error: wrong number of args\n");
		return (-1);
	}

	void* map = get_map(av[1]);
	if (!map)
	{
		printf("Error: Couldnt map file\n");
		return (-1);
	}

	int newFd = get_new_file_fd("");//TODO: make it append to the executable name
	if (newFd == -1)
	{
		printf("Error: couldnt open new file\n");
		return (-1);
	}

	t_ptrs elfPtrs = {0};
	t_ranges ranges = {0};
	setReleventPointers(map, &elfPtrs, &ranges);

	setSegmentRange(map, &elfPtrs, &ranges);

	setSectionsInSegment(map, &elfPtrs, &ranges);


	unsigned char shellCode[] = {
		0x48, 0xbf, 0xf6, 0xf6, 0xf6, 0xf6, 0xf6, 0xf6,
		0xf6, 0xf6, 0xbe, 0xf0, 0x00, 0x00, 0x00, 0x48,
		0xba, 0xf5, 0xf5, 0xf5, 0xf5, 0xf5, 0xf5, 0xf5,
		0xf5, 0x48, 0x83, 0xfe, 0x00, 0x0f, 0x84, 0x81,
		0x00, 0x00, 0x00, 0x49, 0x89, 0xd0, 0x4d, 0x31,
		0xd2, 0x49, 0xf7, 0xc2, 0x07, 0x00, 0x00, 0x00,
		0x75, 0x2c, 0x4d, 0x89, 0xc1, 0x49, 0xc1, 0xe9,
		0x0c, 0x4d, 0x31, 0xc8, 0x4d, 0x89, 0xc1, 0x49,
		0xc1, 0xe1, 0x19, 0x4d, 0x31, 0xc8, 0x4d, 0x89,
		0xc1, 0x49, 0xc1, 0xe9, 0x1b, 0x4d, 0x31, 0xc8,
		0x49, 0xb9, 0x1d, 0xdd, 0x6c, 0x4f, 0x91, 0xf4,
		0x45, 0x25, 0x4d, 0x0f, 0xaf, 0xc1, 0x4c, 0x89,
		0xd0, 0x48, 0x83, 0xe0, 0x07, 0x48, 0xc1, 0xe0,
		0x03, 0x48, 0x89, 0xc1, 0x4c, 0x89, 0xc2, 0x48,
		0xd3, 0xea, 0x42, 0x30, 0x14, 0x17, 0x49, 0xff,
		0xc2, 0x49, 0x39, 0xf2, 0x75, 0xab, 0xe8, 0x0f,
		0x00, 0x00, 0x00, 0x2e, 0x2e, 0x2e, 0x2e, 0x57,
		0x4f, 0x4f, 0x44, 0x59, 0x2e, 0x2e, 0x2e, 0x2e,
		0x2e, 0x0a, 0x5e, 0xb8, 0x01, 0x00, 0x00, 0x00,
		0xbf, 0x01, 0x00, 0x00, 0x00, 0xba, 0x0f, 0x00,
		0x00, 0x00, 0x0f, 0x05, 0xe9, 0xfb, 0xff, 0xff,
		0xff
	};

	/* now the hard part does .text have space to inject */
	setRangeOfText(map, &elfPtrs, &ranges);
	if (ranges.textIndex == ranges.sectionAfterText)//if .text is at end of file will be handled later because requires extra logic.
	{
		printf("fuck\n");
	}
	else// i got to the point where i can calculate the size of the code cave, i want to now check if the code cave is mapped by the target segment.
	{
		size_t entryPoint = elfPtrs.ehdr->e_entry;
		size_t newEntry = elfPtrs.targetSegment->p_vaddr + elfPtrs.targetSegment->p_filesz;
		int flag =  0x02; // PF_W
		memcpy((void*)(&elfPtrs.pHdrTable[ranges.targetSegment].p_flags), &flag, 4);

		size_t pdataAdd = elfPtrs.targetSegment->p_vaddr;
		size_t encryptSize = elfPtrs.targetSegment->p_memsz;
		size_t offsetToEncriptableData = elfPtrs.targetSegment->p_offset;
		uint64_t encryptKey = generate_key();

		elfPtrs.ehdr->e_entry = newEntry;

		encrypt_data((void *)(map + offsetToEncriptableData), encryptSize, encryptKey);
		
		memmove((void*)(shellCode + 2), &pdataAdd, 8);
		memmove((void*)(shellCode + 11), &encryptSize, 8);
		memmove((void*)(shellCode + 17), &encryptKey, 8);

		memcpy((void*)(shellCode + sizeof(shellCode) - 8), &entryPoint, 8);
		memcpy((void*)(map + elfPtrs.targetSegment->p_offset + elfPtrs.targetSegment->p_filesz), shellCode, sizeof(shellCode));
		// memmove((void*)(map + elfPtrs.targetSegment->p_offset + elfPtrs.targetSegment->p_filesz), shellCode, sizeof(shellCode));
		
		elfPtrs.targetSegment->p_filesz += sizeof(shellCode);
		elfPtrs.targetSegment->p_memsz += sizeof(shellCode);

		write(newFd, map, fileSize);

		printf("text index [%ld] next index [%d]\n", ranges.textIndex, ranges.sectionAfterText);
		printf("text offs [%ld], next offst [%ld]\n", elfPtrs.sHdrTable[ranges.textIndex].sh_offset + elfPtrs.sHdrTable[ranges.textIndex].sh_size, elfPtrs.sHdrTable[ranges.sectionAfterText].sh_offset);
	}


}
