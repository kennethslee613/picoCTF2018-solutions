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

