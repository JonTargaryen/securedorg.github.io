---
layout: default
permalink: /RE102/section3.1/
title: Setup
---
[Go Back to Reverse Engineering Malware 102](https://securedorg.github.io/RE102/)

# Section 3.1: Lab 1 #

Go ahead and open IDAfree and load the malware. Give IDA some time to parse all of the functions. It should begin the analysis in the start function. If you are not in the start function, select the start function from the function tab/window.

## Identifying Delphi ##

The previous page talked about the delphi structure. You should be able to identify the InitExe and the array of classes at offset [dword](https://msdn.microsoft.com/en-us/library/cc230318.aspx?f=255&MSPPError=-2147217396) at 045BB5C.  Double-click on offset dword_45BB5C. Notice that this looks like the array discussed on the previous page. 

*Note: IDAPro provides better delphi library support and will automatically name library references for you.*

*Click Image to Enlarge*
[![alt text](https://securedorg.github.io/RE102/images/delphi2.gif "delphi")](https://securedorg.github.io/RE102/images/delphi2.gif)

---

## Junk Data ##

In the information gathering stage, the strings revealed that there was some junk data being referenced. Let’s actually look how those strings are being referenced in the disassembler. Scroll down until you see some junk strings in the DATA section in the IDA Strings panel.  Each Portable Executable (PE) section has its own purpose. The DATA (.data) section is typically used for hardcoded global and static variables that were initialized at compile time [[1]][1]. This section is more commonly used for storing string references. To see a string referenced in the data section that looks like junk data might be an indicator of foul play.

![alt text](https://securedorg.github.io/RE102/images/PEstructure.png "PEstructure")

## Follow the Junk Data ##

Double-Click the first instance of the junk data. 

![alt text](https://securedorg.github.io/RE102/images/startofjunk.png "startofjunk")

At this point is should show you the location in the IDA View. Scroll up until you see a `unk` reference to the start of this data. It should say `unk_45CCD4`. We want to follow this reference in the code by selecting and then press ‘x’ to open the xrefs menu. This menu shows all the functions and locations that reference the object. Select the only function present and press `ok`.

*Click Image to Enlarge*
[![alt text](https://securedorg.github.io/RE102/images/junkstrings.gif "junkstrings")](https://securedorg.github.io/RE102/images/junkstrings.gif)

IDA should have landed you in the function that is using this data. Notice anything fishy about this function? 

![alt text](https://securedorg.github.io/RE102/images/Raisins_Face.jpg "omg")

It’s calling `VirtualAlloc`.

So we see that VirtualAlloc with size 0x65E4 hex which is 26,084 bytes decimal. The junk data pointer (labeled Junk 2) is about to be used by function sub_407074. Normally when you see a function following VirtualAlloc, it will copy data into the newly created memory location. You should record the contents of Junk 1 because we will need this dword value later. Finally rename function sub_407074 to something like “copy_to_new_mem”.

![alt text](https://securedorg.github.io/RE102/images/VirtualAlloc.png "VirtualAlloc")

## Trace Backwards ##

So now we want to find the route between the **start** function and our renamed function **copy_to_new_mem**. By using xrefs (selecting & pressing x) you can follow all the functions that referenced the function you selected. Scroll up to the top of the functions and see if you can work your way back to the delphi class library array.

Your notes should be something like this:
`Copy_to_new_mem <- sub_45B794 <- sub_45B894 <- sub_45B93C <- 045BB5C (Array)`

Renaming each to something notable like:
`Copy_to_new_mem <- use_junkdata <- before_use_junkdata <- main_function <- 045BB5C (Array)`

Keeping track of this route by the function offset (e.g. 45B93C) allows you to set breakpoints when you start debugging. You know ahead of time where you want to navigate to.

## Recording Control Flow ##

IDA does a lovely job of showing you green and red arrows for control flow instructions in the assembly. You will want to keep track of instructions like cmp, jmp, jnz, jz, jl, jnb, etc. that affect the route. Recording these locations will come in handy when you start debugging and need to manipulate EFlags to change the decision of the jump. 

## Record Anything Interesting ##

As you are building your route, any API call or string is helpful in identifying the purpose of a function. You may change the name of the function depending on what new information you find. For instance, sub_45B93C (a.k.a. main_function) is doing an interesting routine. Can you guess why this function is using GetForegroundWindow, Sleep, then GetForegroundWindow? If not, record and save it for later (Hint: Answer is in Section 5).  These routines may affect the control flow instructions. The example below shows how the success or failure of OutputDebugStringA is compared using `cmp esi,ebx` while `jz` will jump if the result of the comparison is equal to zero. During debugging we may want to manipulate the EFlags so that it will not jump.

![alt text](https://securedorg.github.io/RE102/images/record_interesting.png "interesting")

# Work on Your Own #

Take this time to make some nice travel directions. The next page will have what your directions should look like.

[1]: https://msdn.microsoft.com/en-us/library/ms809762.aspx?f=255&MSPPError=-2147217396

[Section 3 <- Back](https://securedorg.github.io/RE102/section3) | [Next -> Section 3.2](https://securedorg.github.io/RE102/section3.2)
