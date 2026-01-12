#ifndef PACKER_H
#define PACKER_H

//libs
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>


typedef struct s_ptrs
{
	/* data */
	Elf64_Ehdr*	ehdr;
	Elf64_Phdr* pHdrTable;
	Elf64_Phdr* targetSegment;
	Elf64_Shdr* sHdrTable;
	Elf64_Shdr* textSectionHdr;
}			t_ptrs;

typedef struct s_ranges
{
	/* important ranges */
	size_t	segmentSize;
	size_t	segmentStart;
	size_t	segmentEnd;

	size_t	sectionsInSegment;
	
	int		firstSectionInSegment;
	int		lastSectionInSegment;

	size_t codeCaveSz;
	int		sectionAfterText;

	size_t phnum;
	size_t shnum;
	size_t textIndex;
	size_t targetSegment;
}	t_ranges;
//functons
void	*get_map(char *str);
int	get_new_file_fd(char *str);




int	ft_strcmp(const char *s1, const char *s2);
void writeHex(unsigned char c);








#endif