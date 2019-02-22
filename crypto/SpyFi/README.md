# SpyFi

## Analyzing the Program

The first thing we should do is try to figure out what the program is doing, so let's connect to the server and take a look:

```
$ nc 2018shell.picoctf.com 37131
Welcome, Agent 006!
Please enter your situation report: hello world!
ce046744a8001b55f5031288fc983115ff5affb36c681216a9c51e8f21a58aed691761c8573db4e7ea6b58605dd68fbdbea60e88310e765141901edea32afb0eb08059aee9513523b2d9b83cc2c9f16b77d2745f2588e9e5fe4c80ddc873ee7a50721efe9a5b8ceaf737981c0b7f24abd9232464c345bbe4a91c42c14675fa1b1b8e2c6cddc1b1c40f2ee3f87044598eed89cf57604e0c1f8b077cb586dc25edd5568243e255890c313384b9b027fd8b
```

So the program asks us for input and sends us what looks like cipher text afterwards. If we take a look at the source code that they give us, we can get a better understanding of what's going on. I'll be looking at snipets of the source code:

```
agent_code = """flag"""

...

welcome = "Welcome, Agent 006!"
print welcome

sitrep = raw_input("Please enter your situation report: ")
message = """Agent,
Greetings. My situation report is as follows:
{0}
My agent identifying code is: {1}.
Down with the Soviets,
006
""".format( sitrep, agent_code )

message = pad(message)
print encrypt( """key""", message )
```
This is the bulk of the code, and we can see that our input gets stored in a variable called `sitrep` and the flag that we are looking for is in `agent_code`. `message` includes both `sitrep` and `agent_code` inside, and it's being padded and then encrypted with some `"""key"""`.

Now let's take a look at what the `encrypt()` function does:

```
def encrypt(key, plain):
    cipher = AES.new( key.decode('hex'), AES.MODE_ECB )
    return cipher.encrypt(plain).encode('hex')
```
We see that the function takes a `key` and `plain` (plaintext) and returns the plaintext as ciphertext. The first line of the function tells us that the program is using AES ECB encryption. Here's a brief description of how ECB encryptions work (ECB shouldn't be used in real life scenarios): https://ctf101.org/cryptography/what-are-block-ciphers/#electronic-codebook-ecb.

ECB essentially breaks down the plaintext into blocks, encrypts each block, and then combines it to create the ciphertext. This is why we have the `pad()` function, which just pads `message` with trailing 0's until the length of `message` is a multiple of 16.
```
def pad(message):
    if len(message) % 16 != 0:
        message = message + '0'*(16 - len(message)%16 )
    return message
```

Now let's move on to how ECB is being used in this program.

## Structure of the Encryption

We should start by figuring out the size of the blocks that the plaintext is being split into. Since `message` is being padded by 16, the block size is also most likely 16, but we should test to see if that's true. If the blocks are size 16 each, then this is what it would look like, where `{0}` is our input and `{1}` is the flag:

```
message = """Agent,
Greetings. My situation report is as follows:
{0}
My agent identifying code is: {1}.
Down with the Soviets,
006
"""
```

```
		| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
		|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
Block 0:	| A | g | e | n | t | , |\n | G | r | e | e | t | i | n | g | s |
Block 1:	| . |   | M | y |   | s | i | t | u | a | t | i | o | n |   | r |
Block 2:	| e | p | o | r | t |   | i | s |   | a | s |   | f | o | l | l |
Block 3:	| o | w | s | : |\n |{0}|\n | M | y |   | a | g | e | n | t |   | 
Block 4:	| i | d | e | n | t | i | f | y | i | n | g |   | c | o | d | e | 
Block 5:	|   | i | s | : |   |{1}| . |\n | D | o | w | n |   | w | i | t | 
Block 6:	| h |   | t | h | e |   | S | o | v | i | e | t | s | , |\n | 0 | 
Block 7:	| 0 | 6 |\n |
```

Again, we are assuming that each block is of length 16. With this, we can see that if we send `'A' * 11` as our input (as in `AAAAAAAAAAA`), then block 3 should look like:
```
		| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
		|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
Block 3:	| o | w | s | : |\n | A | A | A | A | A | A | A | A | A | A | A |
```
And if we were to send `'A' * 12` as our input, then block 3 should look exactly the same, since the extra `'A'` ends up in the beginning of block 4 (and that should not mess with block 3 at all).

So let's try sending `AAAAAAAAAAA` (`'A' * 11`):

```
Welcome, Agent 006!
Please enter your situation report: AAAAAAAAAAA
ce046744a8001b55f5031288fc983115ff5affb36c681216a9c51e8f21a58aed691761c8573db4e7ea6b58605dd68fbdab4921835ba8362a668cf37d31aca779aeaca2bcf64ed4288cfd207f5e6d5bb4382f6cf8958cf724be0bf19b83c44ee1b94302ebb74b3f7e9c78f8cece361cbeafdb07dd5902e4e72a15c7ec0fed07a2a7185d6a1d244e61c7a6beac5264a179ae95e42f07779a466b0bbefcef0334ce4437689d6901875ea13a57727ddf42e4
```

Since one ascii character is two hex digits, we need to count two hex digits per ascii character. In other words, since one block has 16 ascii characters, one block should contain 32 hex digits. So let's take a look at what block 3 of the cipher text looks like:

```
$ python
Python 2.7.15rc1
>>> cipher = 'ce046744a8001b55f5031288fc983115ff5affb36c681216a9c51e8f21a58aed691761c8573db4e7ea6b58605dd68fbdab4921835ba8362a668cf37d31aca779aeaca2bcf64ed4288cfd207f5e6d5bb4382f6cf8958cf724be0bf19b83c44ee1b94302ebb74b3f7e9c78f8cece361cbeafdb07dd5902e4e72a15c7ec0fed07a2a7185d6a1d244e61c7a6beac5264a179ae95e42f07779a466b0bbefcef0334ce4437689d6901875ea13a57727ddf42e4'
>>> cipher[3 * 32:4 * 32]
'ab4921835ba8362a668cf37d31aca779'
```

Block 3, after being ecnyrpted, is `ab4921835ba8362a668cf37d31aca779`. Now let's confirm this by sending `AAAAAAAAAAAA` (`'A' * 12`):

```
Welcome, Agent 006!
Please enter your situation report: AAAAAAAAAAAA
ce046744a8001b55f5031288fc983115ff5affb36c681216a9c51e8f21a58aed691761c8573db4e7ea6b58605dd68fbdab4921835ba8362a668cf37d31aca7798dc99bc8bfd2973b8b765b0d5eed480377d2745f2588e9e5fe4c80ddc873ee7a50721efe9a5b8ceaf737981c0b7f24abd9232464c345bbe4a91c42c14675fa1b1b8e2c6cddc1b1c40f2ee3f87044598eed89cf57604e0c1f8b077cb586dc25edd5568243e255890c313384b9b027fd8b
```

Again, we look at block 3 of the ciphertext:

```
>>> cipher = 'ce046744a8001b55f5031288fc983115ff5affb36c681216a9c51e8f21a58aed691761c8573db4e7ea6b58605dd68fbdab4921835ba8362a668cf37d31aca7798dc99bc8bfd2973b8b765b0d5eed480377d2745f2588e9e5fe4c80ddc873ee7a50721efe9a5b8ceaf737981c0b7f24abd9232464c345bbe4a91c42c14675fa1b1b8e2c6cddc1b1c40f2ee3f87044598eed89cf57604e0c1f8b077cb586dc25edd5568243e255890c313384b9b027fd8b'
>>> cipher[3 * 32:4 * 32]
'ab4921835ba8362a668cf37d31aca779'
```

We confirmed that block 3's with input `'A' * 11` and `'A' * 12` are the same. We're not quite done yet though. We also have to check that block 3 with input `'A' * 10` will be different from block 3 with input `'A' * 11`. We can see why if we take a look at what block 3 with input `'A' * 10` would look like:

```
		| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
		|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
Block 3:	| o | w | s | : |\n | A | A | A | A | A | A | A | A | A | A |\n |
```

Where does that last `\n` come from? It's from what comes after our input in `message`, since we did not completely fill up the 16 spaces of block 3 (assuming that the block size is 16). So let's test to see if this is true by sending in `AAAAAAAAAA` (`'A' * 10`):

```
Welcome, Agent 006!
Please enter your situation report: AAAAAAAAAA
ce046744a8001b55f5031288fc983115ff5affb36c681216a9c51e8f21a58aed691761c8573db4e7ea6b58605dd68fbddb54f3a3575e26c63c0e12434c4d4aaaee9e908e404313eaec1e41c31bf050cfc139b3e6b199e8a2fb92027f7046b3de6afe9de92c8156e56b85098b5278e3d4ff115e095118645915c5e373d5284e20fedb6451ee78330d873921124a4bcc05baff560bd1b75215fc4815a04787be7e091cf653b40dea8b8ad7285b82cda635
```
```
>>> cipher = 'ce046744a8001b55f5031288fc983115ff5affb36c681216a9c51e8f21a58aed691761c8573db4e7ea6b58605dd68fbddb54f3a3575e26c63c0e12434c4d4aaaee9e908e404313eaec1e41c31bf050cfc139b3e6b199e8a2fb92027f7046b3de6afe9de92c8156e56b85098b5278e3d4ff115e095118645915c5e373d5284e20fedb6451ee78330d873921124a4bcc05baff560bd1b75215fc4815a04787be7e091cf653b40dea8b8ad7285b82cda635'
>>> cipher[3 * 32:4 * 32]
'db54f3a3575e26c63c0e12434c4d4aaa'
```

Block 3 in this case came out to be `'db54f3a3575e26c63c0e12434c4d4aaa'`, which is different from the previous block 3's we found, meaning that the block size is indeed 16.

Now we can move on to actually breaking this encrytpion!

## Breaking the Encryption

I'll briefly explain how we're going to go about breaking this encryption.
First, we need a block of text that we already know (usually our input, since we know what our input is). Let's fill this known block with A's.

```
		| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
		|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
Block 0:	| A | A | A | A | A | A | A | A | A | A | A | A | A | A | A | A |
Block 1:	| s | e | c | r | e | t |   | i | n | f | o | ! | ! | ! | ! | ! |
```

The data in block 1 is the unknown text that we are trying to figure out. We'll call this unkown text `secret`. So how might we go about doing this? First, we send one less A so that one character from `secret` end up at the end of block 0 like so:

```
		| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
		|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
Block 0:	| A | A | A | A | A | A | A | A | A | A | A | A | A | A | A | s |
Block 1:	| e | c | r | e | t |   | i | n | f | o | ! | ! | ! | ! | ! |
```

Then, the program will encrypt blocks 0 and 1, which means that we have the ciphertext of block 0 with 15 A's and one secret character, we'll call this `leak-secret`. So in our perspective, since we don't know what `secret` is, block 0 would look like the following (where `(U)` is an unkown value):
```
		| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
		|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
Block 0:	| A | A | A | A | A | A | A | A | A | A | A | A | A | A | A |(U)|
```

So now, we can brute force all 256 possible hex values in place of `(U)` until we find a match with `leak-secret`. We do this by sending `AAAAAAAAAAAAAAAA(X)` as our input, where `(X)` is the brute forced character. The program will encrypt `AAAAAAAAAAAAAAAA(X)`, after which we can match it up to `leak-secret`. While iterating through the 256 possible hex values, we will reach 0x78 as a match, which is the character `'s'`. So now we know that the first character of `secret` is `'s'`. Then, we continue the pattern with each character in the rest of `secret`:

```
		| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
		|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
Block 0:	| A | A | A | A | A | A | A | A | A | A | A | A | A | A | s | e |
Block 1:	| c | r | e | t |   | i | n | f | o | ! | ! | ! | ! | ! |
```
```
		| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
		|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
Block 0:	| A | A | A | A | A | A | A | A | A | A | A | A | A | s | e | c |
Block 1:	| r | e | t |   | i | n | f | o | ! | ! | ! | ! | ! |
```
```
		| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
		|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
Block 0:	| A | A | A | A | A | A | A | A | A | A | A | A | s | e | c | r |
Block 1:	| e | t |   | i | n | f | o | ! | ! | ! | ! | ! |
```
```
...
```
```
		| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
		|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
Block 0:	| s | e | c | r | e | t |   | i | n | f | o | ! | ! | ! | ! | ! |
Block 1:	
```

In this problem, we know some of the characters immediately following our input text: `'\nMy agent identifying code is: '`. After this string is our flag. Technically we can include the string we know as the `secret` string that we are supposed to find, but that's a lot of useless work. Instead, we'll go about this problem a little differently.

Instead of having the known block be our input, we can just use the known string mentioned in the paragraph before. More specifically, we'll use the 16 characters that come right before the flag: `'ifying code is: '`. Then, we can start leaking the flag.

To do this, we need our known string to fit in a block, meaning that we need to send in a buffer to line up the known string with a block. I will fill my buffer with B's

```
		| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
		|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
Block 0:	| A | g | e | n | t | , |\n | G | r | e | e | t | i | n | g | s |
Block 1:	| . |   | M | y |   | s | i | t | u | a | t | i | o | n |   | r |
Block 2:	| e | p | o | r | t |   | i | s |   | a | s |   | f | o | l | l |
Block 3:	| o | w | s | : |\n | B | B | B | B | B | B | B | B | B | B | B |
Block 4:	| B |\n | M | y |   | a | g | e | n | t |   | i | d | e | n | t |
Block 5:	| i | f | y | i | n | g |   | c | o | d | e |   | i | s | : |   |
Block 6:	|{1}| . |\n | D | o | w | n |   | w | i | t | h |   | t | h | e |
Block 7:	|   | S | o | v | i | e | t | s | , |\n | 0 | 0 | 6 |\n |
```

We see that we need 12 B's to get `'ifying code is: '` properly fitted in Block 5. Now to find each value of the flag, we just have to remove a `B` and then do the brute forcing explained earlier. However, what happens after we delete the last (12th) `B`? We can't figure out all of the flag if the flag happens to be longer than 12 characters because we run out of B's to delete. So, let's just add a bunch more B's!

```
		| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
		|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
Block 0:	| A | g | e | n | t | , |\n | G | r | e | e | t | i | n | g | s |
Block 1:	| . |   | M | y |   | s | i | t | u | a | t | i | o | n |   | r |
Block 2:	| e | p | o | r | t |   | i | s |   | a | s |   | f | o | l | l |
Block 3:	| o | w | s | : |\n | B | B | B | B | B | B | B | B | B | B | B |
Block 4:	| B | B | B | B | B | B | B | B | B | B | B | B | B | B | B | B |
Block 5:	| B | B | B | B | B | B | B | B | B | B | B | B | B | B | B | B |
Block 6:	| B |\n | M | y |   | a | g | e | n | t |   | i | d | e | n | t |
Block 7:	| i | f | y | i | n | g |   | c | o | d | e |   | i | s | : |   |
Block 8:	|{1}| . |\n | D | o | w | n |   | w | i | t | h |   | t | h | e |
Block 9:	|   | S | o | v | i | e | t | s | , |\n | 0 | 0 | 6 |\n |
```

I added 32 more B's, but you can add however many you want, as long as the length of the flag isn't greater than the number of B's. So now we have the known in block 7 and a total of 44 B's, which I found out was enough after testing. Now let's start our code:

```
from __future__ import print_function	# for the use of the end parameter in print functions
from pwn import *		# pwntools is a very helpful tool for connecting to servers and programs. uses python 2
import string 			# for string.printable

context.log_level = 'warn'	# mutes the extra stuff from the remote() function

startOfKnown = 7 * (16 * 2) 	# starting position of known + part of the flag (block 7)
paddingKnown = 12 + 32		# padding to get the start of the flag at block 7
solution = ''			# current solution
known = 'ifying code is: '	# the known string from the message

# while the end of the flag is not in our solution
while '}' not in solution:
	# we reveal the flag one character at a time
	paddingKnown -= 1

	# open connection
	r = remote('2018shell.picoctf.com', 37131)
	# receive bytes until where we send our input
	r.recvuntil(': ')
	# send the padding for getting parts of the flag
	r.sendline(paddingKnown * 'B')
	# store known + part of the flag that we're testing for (block 7)
	secret = r.recvline()[startOfKnown:startOfKnown + (16 * 2)]
	# close connection
	r.close()
```

As we can see, `startOfKnown` holds the start of block 7, `paddingKnown` is set to 44 (for the 44 B's), `solution` is empty since we don't have any piece of the flag yet, and `known` is set to `'ifying code is: '`. Then, in the while loop, we subtract 1 from `paddingKnown`, which will reduce the number of B's sent one at a time so that we can reveal characters of the flag one at a time. We then connect to the server with `r = remote('2018shell.picoctf.com', 37131)`, and now we can receive and send data with `r`. We receive until we get `': '`, which then means it's time for our input! We send the server `paddingKnown * 'B'` (which will send 43 B's since we want to reveal one character from the flag). We then store the 7th block into `secret`, which should look like this (where `(U)` is the first character of the flag):

```
		| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
		|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
Block 7:	| f | y | i | n | g |   | c | o | d | e |   | i | s | : |   |(U)|
```

Now we have to brute force this character, `(X)`! But how can we test `fying code is: (X)` to see if it is the same as `secret` (block 7)? We can send it as our input, but don't forget to pad the input so that `fying code is: (X)` will fit inside one block. Let's pad it with B's again like so:

```
		| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
		|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
Block 0:	| A | g | e | n | t | , |\n | G | r | e | e | t | i | n | g | s |
Block 1:	| . |   | M | y |   | s | i | t | u | a | t | i | o | n |   | r |
Block 2:	| e | p | o | r | t |   | i | s |   | a | s |   | f | o | l | l |
Block 3:	| o | w | s | : |\n | B | B | B | B | B | B | B | B | B | B | B |
Block 4:	| f | y | i | n | g |   | c | o | d | e |   | i | s | : |   |(X)|
Block 5:	|\n | M | y |   | a | g | e | n | t |   | i | d | e | n | t | i |
Block 6:	| f | y | i | n | g |   | c | o | d | e |   | i | s | : |   |{1}|
Block 7:	| . |\n | D | o | w | n |   | w | i | t | h |   | t | h | e |   |
Block 8:	| S | o | v | i | e | t | s | , |\n | 0 | 0 | 6 |\n |
```

Now we can add some more code:

```
from __future__ import print_function	# for the use of the end parameter in print functions
from pwn import *			# pwntools is a very helpful tool for connecting to servers and programs. uses python 2
import string 				# for string.printable

context.log_level = 'warn'		# mutes the extra stuff from the remote() function

startOfKnown = 7 * (16 * 2) 	# starting position of known + part of the flag (block 7)
startOfTest = 4 * (16 * 2)	# start of our test input after the buffer is applied (block 4)
paddingKnown = 12 + 32		# padding to get the start of the flag at block 7
paddingTest = 11		# padding to test for the flag
solution = ''			# current solution
known = 'ifying code is: '	# the known string from the message
found = False			# debugging purpose
```
Here, I added three more variables, `startOfTest`, `paddingTest`, and `found`. `startOfTest` is just the index of block 4, which is where our test input is going to be. The `paddingTest` is the number of B's we'll be padding our input with to ensure that our test input ends up in block 4. Finally, `found` is just a boolean for debugging purposes.

```
# while the end of the flag is not in our solution
while '}' not in solution:
	# we reveal the flag one character at a time
	paddingKnown -= 1

	# open connection
	r = remote('2018shell.picoctf.com', 37131)
	# receive bytes until where we send our input
	r.recvuntil(': ')
	# send the padding for getting parts of the flag
	r.sendline(paddingKnown * 'B')
	# store known + part of the flag that we're testing for (block 7)
	secret = r.recvline()[startOfKnown:startOfKnown + (16 * 2)]
	# close connection
	r.close()

################################# NEW CODE STARTS HERE #################################

	# take away 1 from the front of known so we can test for more of the flag
	known = known[1:]

	# test for all printable characters (but not \n and the rest
	# because \n causes an EOF error due to sendline()
	for x in string.printable[:-4]:
		# print the character we are testing
		
		# print out the value we're checking
		print(x + '\b', end='')

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
			# add x to the printed characters
			print(x, end='')
			# set found to true so our script knows we found something
			found = True
			# break out of the loop since we found one character
			break

	# if we didn't find a match from all printable strings
	if not found:
		# print error
		print('\nERROR: No match was found.')
		# break out of while loop
		break

	# set found to false again
	found = False

# print a newline at the end to make it look pretty
print()
```

We have to first take away the first value of `known` every time that we test for a new character of the flag. This is because when a new character of the flag is inserted, the front-most character of `known` will need to be removed to make space for the new character of the flag. 

Now for the brute forcing. The for loop starts the brute forcing of each character. I structured the payload for each brute force by starting it with the 11 B's to pad the input so that the rest of the input will fit in `startOfTest` (block 4). After the padding, we send in `known`, then the `solution` we have so far (but only the last 15 characters of it!), and then the character we are brute forcing, `x`. The reason for using only the last 15 characters of `solution` is at some point, the length of `known` will end up being 0, since we continue to remove the front character. Then, if we want to leak one unknown character from the flag, we can only use 15 characters of the solution we have so far. That will leave one space empty at the end for the brute forced character, totalling 16 characters for the full block. Then we store block 4 of the ciphertext sent back to us into `test`.

Now comes the building of the solution. Anytime that `test == solution`, that means that the character we brute forced was a match! So we simply add this character to our list of solutions, print it onto the screen, and then break out of the for loop. 

That's it! Our solver should now be working, and it will print out the flag for us after a minute or so: 
```
$ python SpyFi-script.py 
picoCTF{@g3nt6_1$_th3_c00l3$t_9451543}
```

Thanks for reading, and if you have any questions or anything is unclear, feel free to email me at kennethslee.613@gmail.com.