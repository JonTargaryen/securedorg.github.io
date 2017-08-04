---
layout: default
permalink: /RE102/section5.1/
title: Setup
---
[Go Back to Reverse Engineering Malware 102](https://securedorg.github.io/RE102/)

# Section 5.1: Debugging #

Debugging should be your last resort because it can be time consuming. The purpose of doing static analysis is to know where you are. Be sure to take a VM snapshot before you begin debugging. This snapshot will come in handy when you accidently run the malware sample. Frequent VM snapshots save your debugging work so you won’t lose your place. You can always revert back to your last snapshot.

## Create the Breakpoints ##

Open decrypted_shellcode.exe in x32dbg.

At this point you should have recorded the following functions and locations:
1. `sub_402B1C` @ `00401D9B` - The function the loads the libraries
2. `sub_4014AA` @ `0040560B` - The function that checks for sample, sandbox, and virus
3. `jz loc_405272` @ `004019E4` - The jump to modify the EFlags if necessary
4. `jnz loc_405277` @ `0040526C` - The jump to modify the EFlags if necessary
5. `loc_405272` @ `00405272` - The location that calls the unknown API
6. `loc_405277` @ `00405277` - The location that calls the unknown API

Place a breakpoint with x32dbg using the command line. Example: `bp 00401D9B`

![alt text](https://securedorg.github.io/RE102/images/breakpoint.png "breakpoint")

Now press **F9** to run the program to breakpoints until you reach `004019E4`.

![alt text](https://securedorg.github.io/RE102/images/4019E4.png "4019E4")

Scroll down to check out offset `00405272`. Looks like the `[esp+1C]` is using Path Windows APIs to check the strings against sample, sandbox, and virus. Since your exe name is and path does not contain these words, it will not jump. So you won’t need to force the jump. Keep pressing **F8** (step over) until you reach offset `00405277`.

![alt text](https://securedorg.github.io/RE102/images/405272.png "405272")

**Congrats!** This was the first evasion technique you worked through. Now that we know what these API calls are, you should be filling in your IDA comments with these APIs. 

## Adding Resources ##

Step **F7** the program until you reach the next function `sub_40487D`. Be sure to record the arguments pushed onto the stack. Step Into **F7** function `sub_40487D`. Next step until you reach `00401632` and look down to `00401645`. The calls to GetModuleHandle and FindResource means it’s about to access a resource in the exe.

This is typically how you get a resource from an exe:

```
HMODULE hModule = GetModuleHandle(NULL); // get the handle to self (exe)
HRSRC hResource = FindResource(hModule, MAKEINTRESOURCE(RESOURCE_ID), RESOURCE_TYPE); 
HGLOBAL hMemory = LoadResource(hModule, hResource);
DWORD dwSize = SizeofResource(hModule, hResource);
LPVOID lpAddress = LockResource(hMemory);
```

When you turned the shellcode into an exe it did not include any resources. Remember that the original exe is where this shellcode gets executed. So you will need to get the resource from the original exe and import them into shellcode exe. The argument passed to the function `sub_40487D` was 0xE38 which is 1000 in decimal. If you keep stepping through function `sub_40487D` you will see the routine above and notice that the argument to find the resource is 1000.

```
HRSRC WINAPI FindResource(
  _In_opt_ HMODULE hModule,
  _In_     LPCTSTR lpName, //ID of the resource
  _In_     LPCTSTR lpType
);
```
![alt text](https://securedorg.github.io/RE102/images/LoadResource.png "LoadResource")

Close x32dbg while you edit the decrypted_shellcode.exe.

Open up the original exe in CFF explorer and look for the resource 1000. Next export this resource under Resource Editor, right-click and Save Resource (RAW). Take a moment and look at the data of this resource. Hint: looks like more junk data. 

![alt text](https://securedorg.github.io/RE102/images/resource.png "resource")

Once you exported the resource 1000, open the decrypted_shellcode.exe with CFF explorer. In the Resource Editor add Add Custom Resource (Raw) with the id of 1000. It should mirror the original exe. Afterwards open decrypted_shellcode.exe with x32dbg again. Navigate back to function `sub_40487D` or just set a breakpoint at `0040487D` and run until that function.

## Saving Junk and Chunks in Memory ##

Keep stepping until you reach `0040416F` where you will see that the resource is being placed into a new memory allocation. Remember that VirtualAlloc is typically followed by a Move function. After the VirtualAlloc function is returned make sure you note the address of the newly allocated memory. This function will return that memory address value in the `eax` register. Once the value is in `eax` right click on the address and view the address in any of the dumps.

![alt text](https://securedorg.github.io/RE102/images/savingresource.png "savingresource")

Once you are done stepping through function `sub_40487D` step until you reach `loc_4014C2`.

![alt text](https://securedorg.github.io/RE102/images/allocate318.png "allocate318")

The size 0x318 is a common theme for the next couple of function calls. This is where you will see another routine of VirtualAlloc and Move.  It will store the first 0x318 bytes into the newly allocated memory.

![alt text](https://securedorg.github.io/RE102/images/Virtualloc318.png "Virtualloc318")

![alt text](https://securedorg.github.io/RE102/images/move_decrypt.png "move_decrypt")

Does function `sub_403BC2` look familiar? Here is the breakdown:
```
Arg_0 CopiedData+offset 20h
Arg_1 0x2F8 size
Arg_2 CopiedData
Arg_3 0x20 size
```

Why offset 0x20? Here is the dump of the CopiedData:

![alt text](https://securedorg.github.io/RE102/images/20bytesof318.png "20bytesof318")

At this point it’s too early to guess what this data does.
```
78 95 4D 26 0A C4 55 94 74 AF 5A 78 33 71 58 EB CD 05 B3 D6 5A B7 D6 05 43 D8 1A 7D 4A B6 EA 10
```
In IDA, glance through function `sub_403BC2`. There are 3 hints that give away what this function is doing.
* The use of 0x100 and 0x20
* Multiple loops
* The use of XOR

If you remember from the previous Section 4, multiple loops and the use XOR is indicative of being some kind of crypto algorithm. There is a theme of crypto here but there just a slight difference. The use of anding a value with 800000FFh is also a form of modulo for `X mod 256`. Earlier we saw that the modified RC4 algorithm was using a delphi mod function instead.

Looks like the is using RC4 again, but you might want to step through the algorithm to confirm if it’s true RC4 or modified RC4 like from Section 4. The first 32 bytes (0x20) decrypted the rest of the CopiedData 760 bytes (0x2F8). Be sure to save the address of this memory in your notes and renaming functions in IDA because you will need this information for Section 6.

Step through until you reach `loc_401CCA` and continue to the next page.

[Section 5 <- Back](https://securedorg.github.io/RE102/section5) | [Next -> Section 5.2](https://securedorg.github.io/RE102/section5.2)
