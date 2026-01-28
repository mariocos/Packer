NAME = lib_asm.a
SRCS = decrypt.s
		
OBJ = $(SRCS:.s=.o)

ASM = nasm
ASM_FLAGS = -f elf64
AR = ar rcs

all: $(NAME)

$(NAME): $(OBJ)
	$(AR) $(NAME) $(OBJ)

%.o: %.s
	$(ASM) $(ASM_FLAGS) $< -o $@

clean:
	rm -f $(OBJ) $(NAME)