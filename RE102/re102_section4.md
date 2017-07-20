---
layout: default
permalink: /RE102/section4/
title: Setup
---
[Go Back to Reverse Engineering Malware 102](https://securedorg.github.io/RE102/)

# Section 4: Identifying Encrypted Data #

![alt text](https://securedorg.github.io/RE102/images/Section6_intro.gif "intro")

This section will focus on generically recognizing encryption routines. In the previous section, we left off at sub_45B5AC. As you can only guess, this malware is actually using a crypto algorithm here. We can assume this based on a few initial indicators:
Suspicious Function Arguments (e.g., large amounts of bytes used for allocation)
* Multiple Loops
* Usage of XOR
* Suspicious Instructions (i.e NOP)

## Suspicious Function Arguments ##

Decrypting data usually requires a few arguments to perform the encryption routine:

1. Key
2. Encrypted Data
3. Destination for Decrypted Data

Let’s look at the arguments for function `sub_45B5AC`. Remember in RE101, section 1.3 explained that assembly function calls have arguments pushed onto the stack. So they are numbered in reverse order. In the image below we can see it’s pushing 4 times and saving 3 objects in 3 different registers (ecx, edx, eax).

![alt text](https://securedorg.github.io/RE102/images/Section4_functionargs.png "func_args")

We know what some of these values already mean based on the previous section. We know that it recently called VirtualAlloc and moved that huge junk 2 data blob into the new memory and stored it in `[ebp+var_BEEB]`. We also know that the size of that data which is 0x65E4. If you click on `unk_45CCB4`, this data is only 32 bytes long or 0x20. So let’s build the pseudo code for this function.

```
eax = size_of_junk2
edx = size_of_small_junk
ecx = small_junk unk_45CCB4
sub_45B5AC( 0x100, 0xBEE2, junk2, 0x1F)
``` 

Let’s rename it all:

```
eax = data_size
edx= key_size
ecx = key
decrypt(0x100, 0xBEE2, encrypted_data, 0x1F)
```

Now all we need to know is what 0x100 and 0xBEE2 represent and you might not know until you start to break down the decrypt function. Hint: 0xBEE2 is 48,866 bytes. This is large enough to be a new exe. 

## Multiple Loops ##

If you have taken any type of crypto class, they should go over 2 types of encryption: symmetric and asymmetric. We know that most of these algorithms perform some kind of looping over each character. Let’s take a look at a symmetric block cipher algorithm for example:

![alt text](https://securedorg.github.io/RE102/images/cipher.png "block_cipher")

For every subkey K in this algorithm, it has to loop through each K to XOR and Swap. In the disassembly you will be able to see this looping, incrementing, and swapping action going on. Now let’s look at sub_45B5AC.

![alt text](https://securedorg.github.io/RE102/images/Section4_looping.png "looping")

There are actually multiple loops happening in this function. Section 4.1 will go over how identifying this algorithm. This section focuses on just recognizing crypto.

## Usage of XOR ##

The use of XOR is quite common in crypto algorithms. Like in the block cipher algorithm above the circle with a cross inside represents the XOR symbol. In assembly, you typically want to find an XOR instruction with 2 different registers. Avoid instructions like `xor eax, eax` because this means it’s clearing register eax. You should see  `xor [esi], al` in  function sub_45B5AC.

## Suspicious Instructions ##

Using special instructions like NOP is not indicative of a decryption function. However it’s an indicator that the malware author didn’t want the function to be analyzed and detected. Inserting NOPs changes the bytecode making it harder for AV signatures to detect the byte patterns. All these NOPs means we are in the right spot to start digging deeper.

The next page will go over identifying which decryption algorithm this malware is using.

[Section 3.2 <- Back](https://securedorg.github.io/RE102/section3.2) | [Next -> Section 4.1](https://securedorg.github.io/RE102/section4.1)
