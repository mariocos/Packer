#include "packer.h"


unsigned char payload_shellcode[] = {
    0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
    0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1
    0x48, 0x8d, 0x35, 0x0d, 0x00, 0x00, 0x00, // lea rsi, [rip+13] (points to "....")
    0x48, 0xc7, 0xc2, 0x0d, 0x00, 0x00, 0x00, // mov rdx, 13
    0x0f, 0x05,                               // syscall
    0xeb, 0x0d,                               // jmp over the string
    '.', '.', '.', 'W', 'O', 'O', 'D', 'Y', '.', '.', '.', '\n', 0x00,
    // --- JUMP STUB ---
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, OEP
    0xff, 0xe0                                                 // jmp rax
};
// the chances of this being 100% correct are not 100%

/*

*/
void	setReleventPointers(void* map, t_ptrs* elfPtrs, t_ranges* ranges)
{
	// ELF header
	Elf64_Ehdr* eHdr = map;
	printf("Inside setRelevant pointers:%lx\n", eHdr->e_entry);
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
		if (nextSection == ranges->textIndex && ht[i].sh_offset > elfPtrs->textSectionHdr->sh_offset)
			nextSection = i;
		else if (ht[i].sh_offset > elfPtrs->textSectionHdr->sh_offset && ht[i].sh_offset < ht[nextSection].sh_offset)
			nextSection = i;
	}
	ranges->sectionAfterText = nextSection;
}

void finalize_and_inject(int newFd, void* map, t_ptrs* ptrs, t_ranges* ranges, char *dest_name) {
	printf("%d\n", __LINE__);
    struct stat st;
    fstat(open("woody", O_RDONLY), &st); // Assuming you want the original size
    
	printf("%d\n", __LINE__);
    // 1. Calculate the new Entry Point
    // It will be at the end of the existing file
    Elf64_Addr old_oep = ptrs->ehdr->e_entry;
    off_t file_end_offset = lseek(newFd, 0, SEEK_END); 
    // If the file is empty, we write the original map first
    // Since we want a clone, let's write the whole mapped file first:
    
    // 2. Patch the Header clones in memory before writing
    // Update Entry Point to the virtual address at the end of the segment
	printf("%d\n", __LINE__);
    Elf64_Addr new_vaddr = ptrs->targetSegment->p_vaddr + ptrs->targetSegment->p_filesz;
	printf("%d|%p|%lx|\n", __LINE__, ptrs->ehdr, ptrs->ehdr->e_entry);
    ptrs->ehdr->e_entry = new_vaddr;

    // Update the PT_LOAD segment sizes
	printf("%d\n", __LINE__);
    size_t total_payload_sz = sizeof(payload_shellcode);
    ptrs->targetSegment->p_filesz += total_payload_sz;
    ptrs->targetSegment->p_memsz += total_payload_sz;

    // Update .text section size so tools like 'objdump' see the code
    ptrs->textSectionHdr->sh_size += total_payload_sz;

    // 3. Patch the Jump Stub with the Old Entry Point (OEP)
    // The stub starts 12 bytes from the end of our payload array
	printf("%d\n", __LINE__);
    memcpy(&payload_shellcode[total_payload_sz - 10], &old_oep, sizeof(old_oep));

    // 4. Perform the actual file construction
    // Use the fd we got from get_new_file_fd
    int src_fd = open(dest_name, O_RDONLY); // You'd pass av[1] here
    fstat(src_fd, &st);
    
    // Write the modified original content
	printf("%d\n", __LINE__);
    write(newFd, map, st.st_size);
    // Append the payload (which now contains the jump back to OEP)
    write(newFd, payload_shellcode, total_payload_sz);
    
    close(src_fd);
	printf("%d\n", __LINE__);
    printf("Successfully injected. New EIP: 0x%lx | OEP: 0x%lx\n", new_vaddr, old_oep);
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


	/* now the hard part does .text have space to inject */
	setRangeOfText(map, &elfPtrs, &ranges);
	if (ranges.textIndex == ranges.sectionAfterText)//if .text is at end of file will be handled later because requires extra logic.
	{
		// printf("fuck\n");
	}
	else// i got to the point where i can calculate the size of the code cave, i want to now check if the code cave is mapped by the target segment.
	{
		printf("text index [%ld] next index [%d]\n", ranges.textIndex, ranges.sectionAfterText);
		printf("text offs [%ld], next offst [%ld]\n", elfPtrs.sHdrTable[ranges.textIndex].sh_offset + elfPtrs.sHdrTable[ranges.textIndex].sh_size, elfPtrs.sHdrTable[ranges.sectionAfterText].sh_offset);
	}
		finalize_and_inject(newFd,map,&elfPtrs,&ranges, av[1]);


}
