from pwn import *
import string

startOfFlag = 7 * 32
startOfTest = 4 * 32
padding1 = 12 + 16 + 16
padding2 = 11
solution = ''
known = 'ifying code is: '
found = False

while '}' not in solution:
	padding1 -= 1
	known = known[1:]
	r = remote('2018shell.picoctf.com', 37131)
	r.recvuntil(': ')
	r.sendline(padding1 * 'B')
	secret = r.recvline()[startOfFlag:startOfFlag + 16 * 2]
	r.close()

	for x in string.printable[:-4]:
		print(x)
		r = remote('2018shell.picoctf.com', 37131)
		r.recvuntil(': ')
		r.sendline((padding2 * 'B') + known + solution[-15:] + x)
		test = r.recvline()[startOfTest:startOfTest + 16 * 2]
		r.close()

		if test == secret:
			solution += x
			print(solution)
			found = True
			break

	if not found:
		print('ERROR')
		break
	found = False

print(solution)