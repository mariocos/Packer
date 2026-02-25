#include "packer.h"

extern size_t fileSize;

void	*get_map(char *str)
{
	if (!str)
		return (NULL);
	int fd = open(str, O_RDONLY);
	if (fd < 0)
	{
		write(2, "problem opening file\n", 21);
		return (NULL);
	}
	fileSize = lseek(fd, 0, SEEK_END);
	void	*map = mmap(NULL, fileSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED)
	{
		write(2, "problem mapping file\n", 21);
		close(fd);
		return (NULL);
	}
	return (map);
}

int	get_new_file_fd(char *str)
{
	(void)str;//TODO: append this to file name
	char new_file_name[6] = "woody";
	int fd = open(new_file_name, O_WRONLY | O_CREAT | O_APPEND, 0644);
	return (fd);
}


int	ft_strcmp(const char *s1, const char *s2)
{
	if (s1 == NULL || s2 == NULL)
		return (0);
	while (*s1 && *s2 && (*s1 == *s2))
	{
		if (!*s1 || !*s2)
			break ;
		s1++;
		s2++;
	}
	return (*(const unsigned char *)s1 - *(const unsigned char *)s2);
}

void writeHex(unsigned char c)
{
	unsigned char div, rest = 0;
	div = c / 16 + '0';
	rest = c % 16 + '0';
	write(1, "0x", 2);
	write(1, &div, 1);
	write(1, &rest, 1);
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