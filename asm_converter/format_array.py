import sys

def format_as_c_array(bytes_per_line):
    # Read hex bytes from stdin
    input_data = sys.stdin.read().strip()
    
    if not input_data:
        return
    
    hex_bytes = input_data.split()
    
    formatted_bytes = [f"0x{b}" for b in hex_bytes]
    
    print("unsigned char shellCode[] = {")
    
    for i in range(0, len(formatted_bytes), bytes_per_line):
        line_chunk = formatted_bytes[i : i + bytes_per_line]
        
        line_str = ", ".join(line_chunk)
        
        if i + bytes_per_line < len(formatted_bytes):
            print(f"    {line_str},")
        else:
            print(f"    {line_str}")
            
    print("};")

if __name__ == "__main__":
    format_as_c_array(8) # This is the number of bytes in each line