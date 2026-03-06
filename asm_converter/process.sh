#!/bin/bash

# 1. Extract the .text section to binary
objcopy -O binary --only-section=.text shell.o shellcode.bin

# 2. Get the hex and pipe it to Python
# We use -v to ensure all bytes are shown and formatting to get raw hex
hexdump -v -e '1/1 "%02x "' shellcode.bin | python3 format_array.py
