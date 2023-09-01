---
weight: 5
title: "UIU CTF 2023"
date: 2023-07-04T17:55:28+08:00
lastmod: 2023-07-04T17:55:28+08:00
draft: false
author: "1259iknowthat"
description: "Some Misc challenges from UIU CTF 2023 🪟"
images: []
resources:
- name: "featured-image"
  src: "featured-image.png"

tags: ["Misc"]
categories: ["WriteUps"]

twemoji: false
lightgallery: true
---


Some Misc challenges from UIU CTF 2023 🪟

<!--more-->

## Preface

A few days ago, I participated a fun CTF contest with my team and solved a few misc challenges. Although they are all easy, I still learn something from them and want to keep a note here for the future.

{{< image src="/images/writeups/uiu/rank.png" caption="Solves" >}}

_____

## Corny Kernel

{{< admonition >}}
Use our corny little driver to mess with the Linux kernel at runtime!

$ socat file:$(tty),raw,echo=0 tcp:corny-kernel.chal.uiuc.tf:1337
{{< /admonition >}}

After connecting to the server, I noticed there was a kernel module file in gzip compressed format. The challenge also gave us the source code of this so let's check it out.

```c
// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

extern const char *flag1, *flag2;

static int __init pwny_init(void)
{
	pr_alert("%s\n", flag1);
	return 0;
}

static void __exit pwny_exit(void)
{
	pr_info("%s\n", flag2);
}

module_init(pwny_init);
module_exit(pwny_exit);

MODULE_AUTHOR("Nitya");
MODULE_DESCRIPTION("

**uiuctf23");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
```

Hmmmm, I guess we can just load it then unload to see the flag.

You can use `insmod` and `rmmod` to load and unload the module.

{{< image src="/images/writeups/uiu/kernel1.png" caption="First part of the flag" >}}

As you can see, we have the first part of the flag. The last is in kernel log, use `dmesg` to see it.

{{< image src="/images/writeups/uiu/kernel2.png" caption="Last part" >}}

##### FLAG: 

**uiuctf{m4ster_k3rNE1_haCk3r}**

____

## vimjail series

### vimjail1

{{< admonition >}}
Connect with socat file:$(tty),raw,echo=0 tcp:vimjail1.chal.uiuc.tf:1337. You may need to install socat.
{{< /admonition >}}

If you connect to the server, you will get into vim environment. You can't type anything and it's almost impossible to get out of this.

{{< image src="/images/writeups/uiu/vimenv.png" caption="Vim session" >}}

What do we do now? Let's see the attachments. We have four files but we just need to pay attention to `entry.sh` and `vimrc`.

```sh
#!/usr/bin/env sh

chmod -r /flag.txt

vim -R -M -Z -u /home/user/vimrc
```

So they use RMZu flag in vim usage.

```
set nocompatible
set insertmode

inoremap <c-o> nope
inoremap <c-l> nope
inoremap <c-z> nope
inoremap <c-\><c-n> nope
```

They mapped 4 combination to nope which means they will do nothing. The point is using these combination to get out of Insert mode for us to type ":" related commands.

I've tried many combinations and this worked for me: "<c-\\>\<c-o>"

{{< image src="/images/writeups/uiu/insert1.png" caption="Into Insert mode" >}}

We escaped!!!

{{< image src="/images/writeups/uiu/flag1.png" caption="Got the flag" >}}

You can read from here to know why we can execute commands in that mode: [Link](https://www.quora.com/What-is-insert-Visual-mode-in-Vim-How-can-I-cut-copy-and-paste-in-that-mode)

##### FLAG: 

**uiuctf{n0_3sc4p3_f0r_y0u_8613a322d0eb0628}**

____

### vimjail2

{{< admonition >}}
Connect with socat file:$(tty),raw,echo=0 tcp:vimjail2.chal.uiuc.tf:1337. You may need to install socat.
{{< /admonition >}}
    
Same problem, different approaches.

```sh
#!/usr/bin/env sh

vim -R -M -Z -u /home/user/vimrc -i /home/user/viminfo

cat /flag.txt
```

In this challenge, we need to exit vim to see the flag.

```
set nocompatible
set insertmode

inoremap <c-o> nope
inoremap <c-l> nope
inoremap <c-z> nope
inoremap <c-\><c-n> nope

cnoremap a _
cnoremap b _
cnoremap c _
cnoremap d _
cnoremap e _
cnoremap f _
cnoremap g _
cnoremap h _
cnoremap i _
cnoremap j _
cnoremap k _
cnoremap l _
cnoremap m _
cnoremap n _
cnoremap o _
cnoremap p _
cnoremap r _
cnoremap s _
cnoremap t _
cnoremap u _
cnoremap v _
cnoremap w _
cnoremap x _
cnoremap y _
cnoremap z _
cnoremap ! _
cnoremap @ _
cnoremap # _
cnoremap $ _
cnoremap % _
cnoremap ^ _
cnoremap & _
cnoremap * _
cnoremap - _
cnoremap + _
cnoremap = _
cnoremap ` _
cnoremap ~ _
cnoremap { _
cnoremap } _
cnoremap [ _
cnoremap ] _
cnoremap \| _
cnoremap \ _
cnoremap ; _
cnoremap < _
cnoremap > _
cnoremap , _
cnoremap . _
cnoremap / _
cnoremap ? _
```

But they mapped all of the keys to "_". Or maybe not all of the keys :D. If you notice, the "q" key and ":" key are not mapped to anything which means we can do ":q" to exit as usual.

Same method but this time we will type ":q" to exit.

{{< image src="/images/writeups/uiu/quit.png" caption="Now we can type :q" >}}

Got the flag here:

{{< image src="/images/writeups/uiu/flag2.png" caption="Got the flag when exit Vim" >}}

##### FLAG: 

**uiuctf{&lt;left&gt;&lt;left&gt;&lt;left&gt;&lt;left&gt;_c364201e0d86171b}**

____

### vimjail1.5

{{< admonition >}}
Fixed unintended solve in vimjail1

Connect with socat file:$(tty),raw,echo=0 tcp:vimjail1-5.chal.uiuc.tf:1337. You may need to install socat.
{{< /admonition >}}
  
LOL, they fixed the old approach 🥲 
    
What's different with new `vimrc`?
    
```
set nocompatible
set insertmode

inoremap <c-o> nope
inoremap <c-l> nope
inoremap <c-z> nope
inoremap <c-\> nope
```

They replaced <c-\\>\<c-n> with <c-\\>. Now we can not use the same method as vimjail1 anymore.
    
After a few hours of trying combinations. I found this [document](https://vimdoc.sourceforge.net/htmldoc/insert.html) on the Internet.
    
Here's the interesting part:    
    
{{< image src="/images/writeups/uiu/com.png" caption="We can use this to send our payload" >}}

Ohh, how about we send "\\\<c-o>" instead?
Let's try it.
    
{{< image src="/images/writeups/uiu/mode.png" caption="Can type right now!" >}}

Now I have entered expression mode. 
    
{{< image src="/images/writeups/uiu/insert2.png" caption="Into Insert mode" >}}

Successfully escaped with our payload!!
    
{{< image src="/images/writeups/uiu/flag3.png" caption="Flag here guys!" >}}

##### FLAG: 

**uiuctf{ctr1_r_1s_h4ndy_277d0fde079f49d2}**

____

### vimjail2.5

{{< admonition >}}
Fixed unintended solve in vimjail2

Connect with socat file:$(tty),raw,echo=0 tcp:vimjail2-5.chal.uiuc.tf:1337. You may need to install socat.
{{< /admonition >}}

Same challenge, same approach. But this time, as an improvement of vimjail2, this chal still mapped all of the keys except "q" and ":" to "_".
    
So the question is: How to bypass it?

Let's take a look back at `vimrc` file. It mapped the keys not the combination so we can still use "<c-o>" as payload. This time we will not type it but press Ctrl-O into our input.
    
{{< image src="/images/writeups/uiu/mode2.png" caption="Payload" >}}

And here is the result:
    
{{< image src="/images/writeups/uiu/flag4.png" caption="Flag here LMAO" >}}

##### FLAG: 

**uiuctf{1_kn0w_h0w_7o_ex1t_v1m_7661892ec70e3550}**

____

## Tornado Warning

{{< admonition >}}
"Check out this alert that I received on a weather radio. Somebody transmitted a secret message via errors in the header! Fortunately, my radio corrected the errors and recovered the original data. But can you find out what the secret message says?\n\nNote: flag is not case sensitive."

Hint 1: The header is encoded with Specific Area Message Encoding.
    
Hint 2: The three buzzes are supposed to be identical, but in this challenge, they are different due to errors.
{{< /admonition >}}

The challenge give us an audio file. If you play it, you'll know that's just a simple weather warning record. What are they hiding from us?
    
As the first hint said, the header is encoded with SAME. Google gave me this [answer](https://emergencyalertsystem.fandom.com/wiki/Specific_Area_Message_Encoding).
    
{{< image src="/images/writeups/uiu/term.png" caption="Data format" >}}

Okay that's easy, just find a tool that support extracting SAME header from the wav file then see what we got.
    
I found this tool:
    
{{< image src="/images/writeups/uiu/tool.png" caption="" >}}

It can be used to read and extract SAME header from wav file, that's what we need to do!
    
{{< image src="/images/writeups/uiu/usage.png" caption="Usage" >}}

Extracting the header:
    
{{< image src="/images/writeups/uiu/header.png" caption="Extracted data" >}}

The flag is embed in the first three lines. If you notice, we just need to extract what's different from the others. If the three are identical, we just need to take one.
    
Wrote a small script here:
    
```py
s = """
ZCZC-UXU-TFR-R18007ST_45-0910BR5-KIND3RWS-
ZCZC-WIR-TO{3018W0R+00T5-09UT115-K_EV/NWS-
ZCZC-WXRCTOR-0D_007+004OR_O1011E@KIND/N}S-
"""

str1, str2, str3 = [i for i in s.splitlines() if i != '']
tmp = []
flag = ''
for i in range(5, len(str1)-2):
    tmp.append(str1[i])
    tmp.append(str2[i])
    tmp.append(str3[i])
    tmp.sort()
    if (tmp[0] == tmp[1]):
        flag += tmp[2]
    else:
        flag += tmp[0]
    tmp = []
print(flag.lower())
```

##### FLAG: 

**uiuctf{3rd_w0rst_tor_outbre@k_ev3r}**
