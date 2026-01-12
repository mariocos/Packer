#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <elf.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/stat.h>
#include <stdio.h>
#define DEBUG

#ifdef DEBUG
	#define DBPRINTF(...) printf("DEBUG: " __VA_ARGS__)
#endif

static inline uint64_t xorshift64(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

void encrypt_data(void *data, size_t size, uint64_t key)
{
    uint8_t *p = (uint8_t *)data;
    uint64_t state = key;

    for (size_t i = 0; i < size; i++)
    {
        if ((i % 8) == 0)
            state = xorshift64(&state);
        p[i] ^= (uint8_t)(state >> ((i % 8) * 8));
    }
}

/* This is not needed at pack-time as the encryption runs on the mmap string and is only needed during load time */
void make_text_writable(void *addr, size_t size)
{
    size_t page = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)addr & ~(page - 1);
    uintptr_t end   = ((uintptr_t)addr + size + page - 1) & ~(page - 1);

    mprotect((void *)start, end - start, PROT_READ | PROT_WRITE | PROT_EXEC);
}

uint64_t generate_key(void)
{
    uint64_t key;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        exit(1);
    if (read(fd, &key, sizeof(key)) != sizeof(key))
        exit(1);
    close(fd);
    return key;
}

void	*get_map(int fd)
{	
	off_t f_size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	void	*map = mmap(NULL, f_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0); 
	if (map == MAP_FAILED)
	{
		write(2, "problem mapping file\n", 21);
		close(fd);
		return (NULL);
	}
	return (map);
}

Elf64_Shdr *get_text_section(void *map, Elf64_Ehdr *ehdr)
{
    Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)map + ehdr->e_shoff);
    
	if (ehdr->e_shstrndx == SHN_UNDEF) return NULL;

    char *shstrtab = (char *)((uint8_t *)map + shdr[ehdr->e_shstrndx].sh_offset);
	
    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        char *name = shstrtab + shdr[i].sh_name;
        
        if (name[0] == '.' && name[1] == 't' && name[2] == 'e' && 
            name[3] == 'x' && name[4] == 't' && name[5] == '\0')
        {
            return &shdr[i];
        }
    }
    return NULL;
}

void write_packed_file(const char *out_name, void *map, ssize_t file_size)
{
    int fd = open(out_name, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (fd < 0)
        exit(1);

    ssize_t written = write(fd, map, file_size);
    if (written != (ssize_t)file_size)
        exit(1);

    close(fd);
}

size_t get_file_size(Elf64_Ehdr *header, Elf64_Phdr *phdrs)
	{
	size_t file_size = 0;
	for (int i = 0; i < header->e_phnum; i++) {
		size_t end = phdrs[i].p_offset + phdrs[i].p_filesz;
		if (end > file_size)
			file_size = end;
		}
	return file_size;
	}

int main(int argc, char *argv[])
{
	if (argc != 2)
		{
		printf("Wrong number of arguments.\n<executable> <file-to-be-packed>\n");
		return -1;
		}

	if (argv[1] == NULL)
		{
		printf("Wrong number of arguments.\n<executable> <file-to-be-packed>\n");
		return -1;
		}
	uint64_t key = generate_key();

	printf("This is the key:%lu\n", key);


	int fd = open(argv[1], O_RDWR);
	if (fd < 0)
	{
		write(2, "problem opening file\n", 21);
		return -1;
	}

	/* double code from get_map() since i am not sure if we can use globals */
	off_t f_size = lseek(fd, 0, SEEK_END); 

	if (f_size < 0)
		{
		write(2, "problem with file size\n", 24);
		return -1;
		}
	lseek(fd, 0, SEEK_SET);
	/******/

	void *map = get_map(fd);

	Elf64_Ehdr	*header = (Elf64_Ehdr *)map;

	Elf64_Shdr *text_sec = get_text_section(map, header);
    
    if (!text_sec)
    {
        write(2, "Error: Could not find .text section\n", 36);
        return -1;
    }

    // Calculate pointer to actual code using the section offset
    void *exec_ptr = (uint8_t *)map + text_sec->sh_offset;
    size_t exec_size = text_sec->sh_size;

    DBPRINTF("Encrypting .text at offset %lx with size %zu\n", 
              text_sec->sh_offset, exec_size);

	printf("%p\n", exec_ptr);
	encrypt_data(exec_ptr, exec_size, key);

	DBPRINTF("157\n");
	write_packed_file("Test", map, (ssize_t)f_size);
	DBPRINTF("159\n");

	return 0;
}