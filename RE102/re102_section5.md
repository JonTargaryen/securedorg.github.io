---
layout: default
permalink: /RE102/section5/
title: Setup
---
[Go Back to Reverse Engineering Malware 102](https://securedorg.github.io/RE102/)

# Section 5: Evasion Techniques #

![alt text](https://securedorg.github.io/RE102/images/Section5_intro.gif "intro")

This section will focus on identifying various Evasion Techniques as well as working around them during the debugging phase. Now that you will be working with an new executable, you will need to create another road map.

Control Flow Obfuscation

You will notice that the shellcode is broken up into extraneous and unnecessary jumps. This is meant to throw off malware analysis with these anti-disassembly techniques. Malware that has this kind of useless instructions is usually processed with some kind of obfuscation kit. Malware authors rarely write new shellcode and will sell, share, or reuse this code.

Going forward, you should be viewing the disassembly in graph mode. It will be easier to read the control flow. Below is an example of the Flow-chart mode of the useless jumps.

![alt text](https://securedorg.github.io/RE102/images/ControlFlowObfuscation.png "ControlFlowObfuscation")

[Section 4.3 <- Back](https://securedorg.github.io/RE102/section4.3) | [Next -> Section 5.1](https://securedorg.github.io/RE102/section5.1)
