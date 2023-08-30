---
weight: 5
title: "Pico CTF 2023"
date: 2023-04-04T17:55:28+08:00
lastmod: 2022-05-13T17:55:28+08:00
draft: false
author: "1259iknowthat"
description: "Full Forensics challenges write-ups from Pico CTF 2023"
images: []
resources:
- name: "featured-image"
  src: "featured-image.png"

tags: ["Forensics"]
categories: ["WriteUps"]

twemoji: false
lightgallery: true
---

Full Forensics challenges write-ups from Pico CTF 2023

<!--more-->

## Foreword

PicoCTF has been one of the greatest cyber security platform for newbie in my opinion. But this year, most of Forensics challenges were so guessy. Five of them were Stegano and one chall is not like Forensics at all. I am very disappointed 🥹.

## hideme

{{< admonition >}}
Every file gets a flag. The SOC analyst saw one image been sent back and forth between two people. They decided to investigate and found out that there was more than what meets the eye.
{{< /admonition >}}

![](images/writeups/pico/flag.png)

This chall is about embed file in a file. You can either use `binwalk` or some hex editors to extract the content of the file. The embed file is just a normal zip file, no password protected so you can unzip it easily.

```
┌─[Green_Onions🧅]-[📂/mnt/hgfs/Local-Lab/Workspace/pico2023]
└─(0)💲binwalk flag.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 512 x 504, 8-bit/color RGBA, non-interlaced
41            0x29            Zlib compressed data, compressed
39739         0x9B3B          Zip archive data, at least v1.0 to extract, name: secret/
39804         0x9B7C          Zip archive data, at least v2.0 to extract, compressed size: 2898, uncompressed size: 3052, name: secret/flag.png
42937         0xA7B9          End of Zip archive, footer length: 22

┌─[Green_Onions🧅]-[📂/mnt/hgfs/Local-Lab/Workspace/pico2023]
└─(0)💲xxd flag.png

(more contents here)
0000a710: a157 0377 7ef2 6f50 4b01 021e 030a 0000  .W.w~.oPK.......
0000a720: 0000 001d 136c 5600 0000 0000 0000 0000  .....lV.........
0000a730: 0000 0007 0018 0000 0000 0000 0010 00ed  ................
0000a740: 4100 0000 0073 6563 7265 742f 5554 0500  A....secret/UT..
0000a750: 03f9 370d 6475 780b 0001 0400 0000 0004  ..7.dux.........
0000a760: 0000 0000 504b 0102 1e03 1400 0000 0800  ....PK..........
0000a770: 1d13 6c56 c83c ed0e 520b 0000 ec0b 0000  ..lV.<..R.......
0000a780: 0f00 1800 0000 0000 0000 0000 a481 4100  ..............A.
0000a790: 0000 7365 6372 6574 2f66 6c61 672e 706e  ..secret/flag.pn
0000a7a0: 6755 5405 0003 f937 0d64 7578 0b00 0104  gUT....7.dux....
0000a7b0: 0000 0000 0400 0000 0050 4b05 0600 0000  .........PK.....
0000a7c0: 0002 0002 00a2 0000 00dc 0b00 0000 00    ...............
```

Once you have the content, just open it up.

![](images/writeups/pico/flag1.png)

##### FLAG: 

**picoCTF{Hiddinng_An_imag3_within_@n_ima9e_92076717}**

____

## PcapPoisoning

{{< admonition >}}
How about some hide and seek heh?
{{< /admonition >}}

So, how to solve this chall? Just use one simple line:

```
┌─[Green_Onions🧅]-[📂/mnt/hgfs/Local-Lab/Workspace/pico2023]
└─(1)💲strings trace.pcap | grep pico

picoCTF{P64P_4N4L7S1S_SU55355FUL_d3d6b5b6}
```

Or you can search the string in wireshark.

{{< image src="/images/writeups/pico/image16.png" caption="Wireshark Log" >}}


##### FLAG: 

**picoCTF{P64P_4N4L7S1S_SU55355FUL_d3d6b5b6}**

____

## who is it

{{< admonition >}}
Someone just sent you an email claiming to be Google's co-founder Larry Page but you suspect a scam. Can you help us identify whose mail server the email actually originated from? Flag: picoCTF{FirstnameLastname}
{{< /admonition >}}

The challenge's description is very dramatic.

First, we open the given file. We can see those informations like: IP address, mail address, name, attached file, etc. So what do we do now? According to the description, this is suspected as a scam email. We has an IP address of the sender: `173.249.33.206`. I will use `whois` command on it to find the one who sent this mail.

```
┌─[Green_Onions🧅]-[📂/mnt/hgfs/Local-Lab/Workspace/pico2023]
└─(0)💲whois 173.249.33.206

(more contents here)

mnt-by:         MNT-CONTABO
created:        2009-12-09T13:41:08Z
last-modified:  2021-09-14T10:49:04Z
source:         RIPE # Filtered

person:         Wilhelm Zwalina
address:        Contabo GmbH
address:        Aschauer Str. 32a
address:        81549 Muenchen
phone:          +49 89 21268372
fax-no:         +49 89 21665862
nic-hdl:        MH7476-RIPE
mnt-by:         MNT-CONTABO
mnt-by:         MNT-GIGA-HOSTING
created:        2010-01-04T10:41:37Z
last-modified:  2020-04-24T16:09:30Z
source:         RIPE

% Information related to '173.249.32.0/23AS51167'

route:          173.249.32.0/23
descr:          CONTABO
origin:         AS51167
mnt-by:         MNT-CONTABO
created:        2018-02-01T09:50:10Z
last-modified:  2018-02-01T09:50:10Z
source:         RIPE

% This query was served by the RIPE Database Query Service version 1.106 (ABERDEEN)
```

Can you see the `person` field? That's the name of the scammer and it's also the flag we are looking for.

##### FLAG: 

**picoCTF{WilhelmZwalina}**

____

## FindAndOpen

{{< admonition >}}
Someone might have hidden the password in the trace file. Find the key to unlock this file. This tracefile might be good to analyze.
{{< /admonition >}}

Take a look at the given files, they're just one pcap file and one pass-protected zip file. We can assuming that the password for it is in the pcap.

{{< image src="/images/writeups/pico/image61.png" caption="Content" >}}

![](images/writeups/pico/image41.png)

Let's analize the traffic. We have MDNS protocol and other sussy protocols which look like hex value. I decided to filter out the data field.

{{< image src="/images/writeups/pico/image21.png" caption="Wireshark Log" >}}

We have many duplicate packets contain the same data. Let's take a look at this packet:

{{< image src="/images/writeups/pico/image14.png" caption="Wireshark Log" >}}

As you can see, all of the packet's fields are informations which are readable ASCII. That's why we have sus protocols look like hex values at the beginning because those ASCII texts has overwritten packet's fields.

Continue follow the trafic then I found the base64 string, decode it and we have the first half of the flag.

![](images/writeups/pico/image51.png)


```
┌─[Green_Onions🧅]-[📂/mnt/hgfs/Local-Lab/Workspace/pico2023/filenopen]
└─(0)💲echo 'VGhpcyBpcyB0aGUgc2VjcmV0OiBwaWNvQ1RGe1IzNERJTkdfTE9LZF8=' | base64 -d
This is the secret: picoCTF{R34DING_LOKd_
```


Use it to unzip the second file then we have full of the flag. Pretty easy, right?

![](images/writeups/pico/image15.png)

##### FLAG: 

**picoCTF{R34DING_LOKd_fil56_succ3ss_5ed3a878}**

____

## MSB

{{< admonition >}}
            This image passes LSB statistical analysis, but we can't help but think there must be something to the visual artifacts present in this image...
{{< /admonition >}}

{{< image src="/images/writeups/pico/Ninja-and-Prince-Genji-Ukiyoe-Utagawa-Kunisada.flag.png" caption="Challenge Image" >}}


We have another picture in this challenge 😔. You can see the title, it said `MSB` which means Most Significant Bit. In case you don't know what it is, I will explain a little bit here:

I will take a random 8 bits number as an example:

10100100

When we read a binary number, we start with the right-most digit and work our way left.

It means we read from right to left.

Order: 7 6 5 4 3 2 1 0

Digits: 1 0 1 0 0 1 0 0

And here are MSB and LSB:

MSB -> 1 010010 0 <- LSB

That's it!

So what is MSB or LSB in steganography?

Assuming that we have one pixel in whatever image. It can be red, blue, yellow, green, etc. But all of the pixel will have 3 basic values, they are R G B values (red, green, blue). Some will have 4, they have A (Alpha) which specifies the opacity for a color. In this challenge, we can put that to one side.

What will happen to those values? RGB(A) use 8 bits for R, G and B. Each color has values ranging from 0 to 255. So you can imagine a pixel will have a structure like this:

(R-value G-value B-value) -> Ex: (63 255 127) = (00111111 11111111 01111111)

If you want to hide one character in this pixel by using LSB technique, for example it's '3' - 011, then it looks exactly like this:

(00111110 11111111 01111111)

For MSB, just reverse the order of the digits when you hide, instead of using the right-most digit, you use the left-most digit.

That's all.

In this challenge, you can use either tools as CyberChef or develop your own script to extract the content.

I'm a lazy person so I use CyberChef to extract:

{{< image src="/images/writeups/pico/image9.png" caption="CyberChef" >}}

##### FLAG: 

**picoCTF{15_y0ur_que57_qu1x071c_0r_h3r01c_9d4ba956}**

____

## Invisible WORDs

{{< admonition >}}
Do you recognize this cyberpunk baddie? We don't either. AI art generators are all the rage nowadays, which makes it hard to get a reliable known cover image. But we know you'll figure it out. The suspect is believed to be trafficking in classics. That probably won't help crack the stego, but we hope it will give motivation to bring this criminal to justice!
{{< /admonition >}}

{{< image src="/images/writeups/pico/image81.png" caption="I'm really panik right now" >}}

Dang, another stegano challenge!

Let's have a look at the bmp picture.

![](images/writeups/pico/backup.bmp)

As you can see, bit planes of the picture is very noisy. I guess the picture has some file embed in it.

Stairing at the pic won't help anything. Let's move on the hex values.

{{< image src="/images/writeups/pico/image11.png" caption="Image's hex" >}}

After 2 hours looking some clues in those hexs, I found something very interesting.

According to [BMP's wikipedia](https://en.wikipedia.org/wiki/BMP_file_format), we have the structure of the BMP that maybe similar to this:

{{< image src="/images/writeups/pico/image7.png" caption="Wiki" >}}

Pay attention to the Pixel Array field. We have hex values that representing RGB values (3 values for RGB, 4 for RGBA):

![](images/writeups/pico/image13.png)

![](images/writeups/pico/image101.png)

Return back to our image. Can you see the unusual thing?

{{< image src="/images/writeups/pico/image12.png" caption="Strange pattern" >}}

The bitmap data of the image follow this format: XX XX YY YY XX XX YY YY ...

At that moment, I guessed XX was bitmap's value and YY was added value. Scroll back to the beginning, I noticed that those values contain `PK` - `50 4B` which is two first hex signatures of zip file.

![](images/writeups/pico/image1.png)

I decided to write a script extract the sussy thing out after cut of the header of the bmp file.


```py
filename = 'output.bmp'
with open(filename, 'rb') as f:
    content = f.read()
noise = content.hex()
data = ""
out = open("extracted.zip", 'wb')
for i in range(0, len(noise), 8):
    data += noise[i:i+4]
out.write(bytes.fromhex(data))
```


Unzip the file, it said there're some trailling datas after the payload but it's ok, at least, it's not corrupted 😁.

![](images/writeups/pico/image8.png)

Open the file (if you decode the name of it by using base64, the result will be like this: frankenstein-test.txt)

{{< image src="/images/writeups/pico/image17.png" caption="Flag is here" >}}

Found the flag.

##### FLAG: 

**picoCTF{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_82b569ad}**

____

## UnforgottenBits

The challenge give us one disk image file. Use Autopsy to load the contents of it. The image is quite huge so Autopsy take a long time to load it.

What do we have here. Hmmm, brower history, log files, those sussy bmp images, some random text??, mails, etc.

I jumped right in log files, they were all about League of Legends, but there is one sussy:

![](images/writeups/pico/image4.png)

So we have the password for `steghide`, `openssl` command that use `key, IV and salt`. I decided to use these things on bmp files.


```
┌─[Green_Onions🧅]-[📂/mnt/hgfs/Local-Lab/Workspace/pico2023/disk/home/yone/gallery]
└─(0)💲steghide extract -sf 1.bmp --passphrase akalibardzyratrundle
wrote extracted data to "les-mis.txt.enc".

┌─[Green_Onions🧅]-[📂/mnt/hgfs/Local-Lab/Workspace/pico2023/disk/home/yone/gallery]
└─(0)💲openssl enc -aes-256-cbc -d -in les-mis.txt.enc -out les-mis.txt -K "58593a7522257f2a95cce9a68886ff78546784ad7db4473dbd91aecd9eefd508" -S "0f3fa17eeacd53a9" -iv "7a12fd4dc1898efcd997a1b9496e7591"
(repeat this process with 2.bmp and 3.bmp)

┌─[Green_Onions🧅]-[📂/mnt/hgfs/Local-Lab/Workspace/pico2023/disk/home/yone/gallery]
└─(0)💲cat les-mis.txt | grep pico

┌─[Green_Onions🧅]-[📂/mnt/hgfs/Local-Lab/Workspace/pico2023/disk/home/yone/gallery]
└─(1)💲cat dracula.txt | grep pico

┌─[Green_Onions🧅]-[📂/mnt/hgfs/Local-Lab/Workspace/pico2023/disk/home/yone/gallery]
└─(1)💲cat frankenstein.txt | grep pico
```


No interesting informations were extracted... Unfortunately 🥲

But the last bmp file which is 7.bmp, we can't use the password to un-steg it. Let's take a look at the notes. Note 1.txt and 2.txt has strings like: chizazerite, guldulheen. Nothing interesting.

![](images/writeups/pico/image5.png)

Hmmmm, look like the phrase `yasuoaatrox...` will be our steghide password but it was not completed.

Then I move on the mails. One of them was talking about erasing sussy mail. I decided to have a look at deleted mails and found this.

![](images/writeups/pico/image10.png)

The mail contain a link. Open it up.

{{< image src="/images/writeups/pico/image6.png" caption="URL" >}}

Hmmmmm 🤔. Are you thinking what Im thinking? Maybe the password is the concatenation of 4 LOL's champion names.

Let's give it a try.

I found a list of name [here](https://www.reddit.com/r/summonerschool/comments/2uhngz/list_of_champions_in_text_format/). Changing them to lowercase then write a simple script.


```py
f = open('name.txt', 'r').readlines()
out = open('wordlist.txt', 'w')
for i in range(len(f)):
    for j in range(len(f)):
        text = 'yasuoaatrox{}{}\n'.format(f[i].strip(), f[j].strip())
        # print(text)
        out.write(text)
```


Use `stegseek` to crack 7.bmp with our wordlist. Tadaaaa\~\~

```
┌─[Green_Onions🧅]-[📂/mnt/hgfs/Local-Lab/Workspace/pico2023/disk/home/yone/gallery]
└─(0)💲stegseek -sf 7.bmp -wl wordlist.txt -v
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek
based on steghide version 0.5.1

[v] Using stegofile "7.bmp".
[v] Running on 4 threads.
[v] Using wordlist file "wordlist.txt".
[v] Added password guess: "".
[v] Added password guess: "7.bmp".
[v] Added password guess: "7".
[i] Found passphrase: "yasuoaatroxashecassiopeia"
[v] reading stego file "7.bmp"...done.
[v] extracting data...done.
[v] checking crc32 checksum... ok
[i] Original filename: "ledger.1.txt.enc".
[i] Extracting to "7.bmp.out".
```

Veri col 😎.

We have another encrypt file. But we can't decrypt it with the same IV or key.


```
┌─[Green_Onions🧅]-[📂/mnt/hgfs/Local-Lab/Workspace/pico2023/disk/home/yone/gallery]
└─(0)💲openssl enc -aes-256-cbc -d -in ledger.1.txt.enc -out ledger.1.txt -pbkdf2 -K "58593a7522257f2a95cce9a68886ff78546784ad7db4473dbd91aecd9eefd508" -S "0f3fa17eeacd53a9" -iv "7a12fd4dc1898efcd997a1b9496e7591"
bad decrypt
4027849B517F0000:error:1C800064:Provider routines:ossl_cipher_unpadblock:bad decrypt:../providers/implementations/ciphers/ciphercommon_block.c:124:
```


What do we do now?

Suddenly, I noticed that 1.txt had some tralling data after it, it's slack data, containing binary string:

![](images/writeups/pico/image2.png)

Look back at the browser history, the user had searched infos about encoding numbers. What has caught my eyes is: [https://www.wikiwand.com/en/Golden_ratio_base](https://www.wikiwand.com/en/Golden_ratio_base)

![](images/writeups/pico/image.png)

Follow that link, I found some informations that can be used to decode the above string. A script to decode the binary string:


```py
string = open("encoded.txt", 'r').readline()
lst = []
for i in range(0, len(string), 15):
    lst.append(string[i:i+15])
    
def decode(phigits):
    int_part, frac_part = phigits.split('.')
    decimal = 0
    for i, digit in enumerate(int_part[::-1]):
        decimal += int(digit) * (1.618 ** i)
    for i, digit in enumerate(frac_part):
        decimal += int(digit) * (1.618 ** (-i-1))
    return round(decimal)

# Debugging:
# print(lst)
# print(decode('00000010100.010'))

for i in lst:
    print(chr(decode(i.strip())),end = "")
```


Output:

```
salt=2350e88cbeaf16c9
key=a9f86b874bd927057a05408d274ee3a88a83ad972217b81fdc2bb8e8ca8736da
iv=908458e48fc8db1c5a46f18f0feb119f
```

Use the given key, IV and salt to decrypt the last encrypted file. We have the result:


```
┌─[Green_Onions🧅]-[📂/mnt/hgfs/Local-Lab/Workspace/pico2023/disk/home/yone/gallery]
└─(0)💲openssl enc -aes-256-cbc -d -in ledger.1.txt.enc -out ledger.1.txt -K "a9f86b874bd927057a05408d274ee3a88a83ad972217b81fdc2bb8e8ca8736da" -S "2350e88cbeaf16c9" -iv "908458e48fc8db1c5a46f18f0feb119f"

┌─[Green_Onions🧅]-[📂/mnt/hgfs/Local-Lab/Workspace/pico2023/disk/home/yone/gallery]
└─(0)💲cat ledger.1.txt | grep picoCTF
picoCTF                                                    UNPAID
    picoCTF{f473_53413d_8a5065d1}
```


##### FLAG: 

**picoCTF{f473_53413d_8a5065d1}**
