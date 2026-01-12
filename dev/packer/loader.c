#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include <string.h>

typedef struct {
    void *file_map;      // Pointer to the start of the mapped file
    void *text_ptr;     // Pointer directly to the .text data
    size_t text_size;   // Size of the .text section
    size_t file_size;   // Total size of the binary
} ElfMetadata;

static inline uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

void decrypt_data(void *data, size_t size, uint64_t key) {
    uint8_t *p = (uint8_t *)data;
    uint64_t state = key;

    for (size_t i = 0; i < size; i++) {
        if ((i % 8) == 0) state = xorshift64(&state);
        p[i] ^= (uint8_t)(state >> ((i % 8) * 8));
    }
}

/* Auxiliary function to handle mapping and indexing */
ElfMetadata get_elf_text_metadata(const char *filename) {
    ElfMetadata meta = {0};
    int fd = open(filename, O_RDONLY);
    if (fd < 0) return meta;

    meta.file_size = lseek(fd, 0, SEEK_END);
    void *map = mmap(NULL, meta.file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (map == MAP_FAILED) return meta;

    // Create a writable copy so we don't need MAP_SHARED or O_RDWR
    meta.file_map = malloc(meta.file_size);
    memcpy(meta.file_map, map, meta.file_size);
    munmap(map, meta.file_size);

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)meta.file_map;
    Elf64_Shdr *shdr = (Elf64_Shdr *)((uint8_t *)meta.file_map + ehdr->e_shoff);
    char *shstrtab = (char *)((uint8_t *)meta.file_map + shdr[ehdr->e_shstrndx].sh_offset);

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (strcmp(shstrtab + shdr[i].sh_name, ".text") == 0) {
            meta.text_ptr = (uint8_t *)meta.file_map + shdr[i].sh_offset;
            meta.text_size = shdr[i].sh_size;
            break;
        }
    }
    return meta;
}


int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input> <key> <output>\n", argv[0]);
        return 1;
    }

    uint64_t key = strtoull(argv[2], NULL, 10);

    // Call our auxiliary function
    ElfMetadata meta = get_elf_text_metadata(argv[1]);
    if (!meta.file_map || !meta.text_ptr) {
        fprintf(stderr, "Failed to map file or find .text section.\n");
        return 1;
    }

    printf("Decrypting .text at %p...\n", meta.text_ptr);
    decrypt_data(meta.text_ptr, meta.text_size, key);

    int out_fd = open(argv[3], O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (out_fd >= 0) {
        write(out_fd, meta.file_map, meta.file_size);
        close(out_fd);
        printf("Success: %s restored.\n", argv[3]);
    }

    free(meta.file_map);
    return 0;
}