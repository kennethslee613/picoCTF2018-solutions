from pwn import *
import string

startOfFlag = 7 * (16 * 2) 	# starting position of known + part of the flag with the buffer we will be giving (block 7)
startOfTest = 4 * (16 * 2)	# start of our test input after the buffer is applied (block 4)
paddingFlag = 12 + 32		# padding to get the start of the flag at block 7
paddingTest = 11			# padding to test for the flag
solution = ''				# current solution
known = 'ifying code is: '	# the known string from the message
found = False				# debugging purpose

# while the end of the flag is not in our solution
while '}' not in solution:
	# we reveal the flag one character at a time
	paddingFlag -= 1

	# open connection
	r = remote('2018shell.picoctf.com', 37131)
	# receive bytes until where we send our input
	r.recvuntil(': ')
	# send the padding for getting parts of the flag
	r.sendline(paddingFlag * 'B')
	# store known + part of the flag that we're testing for (block 7)
	secret = r.recvline()[startOfFlag:startOfFlag + (16 * 2)]
	# close connection
	r.close()

	# take away 1 from the front of known so we can test for more of the flag
	known = known[1:]

	# test for all printable characters (but not \n and the rest
	# because \n causes an EOF error due to sendline()
	for x in string.printable[:-4]:
		# print the character we are testing
		print(x)

		r = remote('2018shell.picoctf.com', 37131)
		r.recvuntil(': ')
		# send padding for test + known + solution we have so far + character we are testing
		r.sendline((paddingTest * 'B') + known + solution[-15:] + x)
		# store the known + solution we have so far + x (block 4)
		test = r.recvline()[startOfTest:startOfTest + (16 * 2)]
		r.close()

		# if the block we're trying to find and the block we're testing are the same
		if test == secret:
			# add x to the solution
			solution += x
			# print the solution we have so far
			print(solution)
			# set found to true so our script knows we found something
			found = True
			# break out of the loop since we found one character
			break

	# if we didn't find a match from all printable strings
	if not found:
		# send error
		print('ERROR: No match was found.')
		# break out of while loop
		break

	# set found to false again
	found = False

# print our final solution
print(solution)