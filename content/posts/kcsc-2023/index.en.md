---
weight: 5
title: "KCSC CTF 2023"
date: 2023-05-17T17:55:28+08:00
lastmod: 2023-05-17T17:55:28+08:00
draft: false
author: "1259iknowthat"
description: "Some Forensics challenges in KCSC CTF 2023"
images: []
resources:
- name: "featured-image"
  src: "featured-image.jpg"

tags: ["Forensics"]
categories: ["WriteUps"]

twemoji: false
lightgallery: true
---

Some Forensics challenges in KCSC CTF 2023

<!--more-->

## Foreword

This CTF event has been one of the greatest events in Viet Nam so far.

My team got second place by chance in 8 hours. Time is short but we got so many works that need to be done, GGWP xD.

{{< image src="images/writeups/kcsc/rank.png" caption="Rank" >}}

____

## Tin học văn phòng

{{< admonition >}}
Hãy phân tích tận gốc rễ mẫu mã độc tống tiền nguy hiểm nhất năm 2023 và tìm flag. 

Zip password: kcscctf

Note: Flag has 2 parts
{{< /admonition >}}

Unzip the given file, we got one doc file. Probably, this one must contain at least a macro.

Let's extract the macro content by using `olevba` tool.

Here is the content of it.

{{< image src="images/writeups/kcsc/ole.png" caption="Source code" >}}

We can see in the flag, it has `$phlac`. It looks like ps1 variable but there's no such a thing appear in the macro. Hmmmmm, sussy isn't it?

Let's go deep down this macro.

First, we have `Auto_Open()` part which maybe, will execute a powershell command. 

```vb
If Val(Application.Version) > 14
```

The macro check if our Office version (Word version in this case) is not from 14 or later, it will not execute.

```vb
cmdType = objCmdShape.Name
cmdCommand = objCmdShape.AlternativeText
cmdParams = Split(objCmdShape.TextFrame.TextRange.Text, "|")
```

The real malicious content is right here. The macro will take `objCmdShape.AlternativeText` as cmd command to execute it. But where to find it?


```vb
Sub AutoOpen()
    Auto_Open
End Sub
Sub Workbook_Open()
    Auto_Open
End Sub
```

Those will call the main function. Not interesting.

So, at this point, we will have two ways to continue the "investigation".

First, we can run this macro with the newest version of Word in a virtual environment. 

{{< image src="images/writeups/kcsc/meme.png" caption="yep" >}}


Since the macro called powershell command, Windows has 90% chance can catch and store it in powershell evtx log file.

<figure class="video_container">
  <video width="640" height="480" controls="true" allowfullscreen="true">
    <source src="https://github.com/1259iknowthat/1259iknowthat.github.io/raw/master/videos/Malware-Behaviour.mkv" type="video/mp4">
  </video>
</figure>

Open Windows Powershell evtx, navigate to the nearest event which has ID 800.

{{< image src="images/writeups/kcsc/pwsh.png" caption="Windows Event Log" >}}

Now, you can decode the base64 string to get the real thing here.

```py
import base64
s = 'JAB7AHAANAB5AEwAMAA0AEQAfQA9ACgAJwBNANkeJwArACcAdAAgACcAKwAnAHMAJwArACcA0R4gACcAKwAnAHQA4AAnACsAJwBpACAAJwArACcAbAAnACsAKAAiAHsAMQB9AHsAMAB9ACIAIAAtAGYAIAAnAHUAIAAnACwAJwBpAMceJwApACsAJwBxAHUAYQAnACsAJwBuACAAJwArACcAdAByAM0eJwArACcAbgBnACAAJwArACcAYwDnHmEAJwArACcAIAAnACsAJwBiACcAKwAnAKEebgAgACcAKwAnABEBJwArACcA4wAgACcAKwAnAGIAyx4nACsAJwAgACcAKwAnAG0AJwArACcA4wAgACcAKwAoACgAIgBoAPMAYQAhACEAYABuABABwx4gACIAKwAnACcAKQArACcAJwApACsAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAIAAnABEBsAEnACwAJwDjHmMAJwApACsAJwAgACcAKwAnAGgAsAHbHicAKwAnAG4AZwAgACcAKwAnAGQAJwArACcAqx5uACAAJwArACcAZwBpAKMeJwArACcAaQAgACcAKwAnAG0AJwArACcA4wAsACAAJwArACcAYgChHm4AJwArACcAIAAnACsAJwBjAKceJwArACcAbgAgACcAKwAoACIAewAxAH0AewAwAH0AIgAgAC0AZgAnAHUAeQAnACwAJwBjAGgAJwApACsAJwDDHicAKwAnAG4AIAAnACsAJwBrAGgAJwArACgAIgB7ADEAfQB7ADAAfQAiAC0AZgAnAKMebgAgACcALAAnAG8AJwApACsAJwAxACcAKwAoACIAewAwAH0AewAxAH0AIgAtAGYAIAAnADAAMAAnACwAJwBrACAAJwApACsAJwB2AOAAJwArACcAbwAgACcAKwAnAHMAJwArACcA0R4gACcAKwAnAHQA4ABpACcAKwAnACAAJwArACgAIgB7ADEAfQB7ADAAfQAiACAALQBmACcAox4nACwAJwBrAGgAbwAnACkAKwAnAG4AJwArACcAIAAnACsAKAAoACIAcwBhAHUAOgBgAG4AMQAwADEAMAAxADAANwAxADEAMgAwADAAMABgAG4AQwBoAOceIAAiACsAJwAnACkAKwAnACcAKQArACcAdADgACcAKwAnAGkAIAAnACsAJwBrAGgAJwArACgAIgB7ADEAfQB7ADAAfQAiACAALQBmACAAJwA6ACcALAAnAG8Aox5uACcAKQArACcAIAAnACsAJwBOACcAKwAnAGcAdQB5ACcAKwAnAMUebgAgACcAKwAnAFQAaAAnACsAKAAiAHsAMQB9AHsAMAB9ACIAIAAtAGYAJwAgACcALAAnAGEAbgBoACcAKQArACgAKAAiAEwAbwBuAGcAYABuAE4AZwDiAG4AIAAiACsAJwAnACkAKwAnACcAKQArACcAaAAnACsAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAIAAnAOAAbgBnACcALAAnACAAJwApACsAJwBNACcAKwAnAEIAIAAnACsAJwBCAGEAJwArACcAbgBrACcAKQANAAoAJgAoACcAQQAnACsAJwBkACcAKwAoACIAewAwAH0AewAxAH0AIgAtAGYAIAAnAGQALQBUACcALAAnAHkAcABlACcAKQApACAALQBBAHMAcwBlAG0AYgBsAHkATgBhAG0AZQAgACgAIgB7ADEAfQB7ADYAfQB7ADAAfQB7ADMAfQB7ADUAfQB7ADQAfQB7ADIAfQAiAC0AZgAgACcAdAAuAFYAJwAsACgAIgB7ADAAfQB7ADEAfQAiAC0AZgAgACcATQBpAGMAcgAnACwAJwBvAHMAJwApACwAJwBpAGMAJwAsACcAaQBzACcALAAoACIAewAxAH0AewAwAH0AIgAgAC0AZgAgACcAcwAnACwAJwBsAEIAYQAnACkALAAnAHUAYQAnACwAJwBvAGYAJwApADsADQAKAHMAZQBUAC0ASQB0AEUATQAgACgAIgBWACIAKwAiAGEAcgBJAGEAYgAiACsAIgBsAGUAOgBoAFYASQA5ADYAIgApACAAKAAgAFsAVAB5AHAARQBdACgAIgB7ADQAfQB7ADUAfQB7ADcAfQB7ADEAfQB7ADMAfQB7ADYAfQB7ADAAfQB7ADgAfQB7ADIAfQAiACAALQBGACAAJwBjAC4ASQBuAFQARQBSACcALAAnAGIAJwAsACcASQBPAE4AJwAsACcAYQAnACwAJwBtAGkAQwByAE8AcwBPAGYAJwAsACcAdAAuAFYAaQBTACcALAAnAHMASQAnACwAJwB1AEEAbAAnACwAJwBBAEMAVAAnACkAIAApACAAOwAgAFMARQB0AC0AaQB0AEUATQAgACgAJwB2AEEAJwArACcAUgBpAGEAYgAnACsAJwBsAGUAOgAnACsAJwBPADcAdgAnACsAJwA4AGsAJwApACAAIAAoACAAIABbAFQAWQBQAEUAXQAoACIAewA0AH0AewA1AH0AewAzAH0AewAyAH0AewAwAH0AewAxAH0AIgAtAEYAIAAnAC4ATQBTAEcAQgBPAHgAUwB0ACcALAAnAHkATABlACcALAAnAC4AVgBJAHMAdQBhAGwAYgBBAFMAaQBjACcALAAnAFMAbwBmAHQAJwAsACcATQBpAEMAJwAsACcAcgBPACcAKQAgACAAKQAgADsAIAAgACAAIAAoACAAZwBlAHQALQB2AEEAUgBJAEEAQgBsAEUAIAAoACcAaAB2AEkAOQAnACsAJwA2ACcAKQAgACAALQB2AGEAbABVAEUATwBOAGwAIAApADoAOgBNAHMAZwBCAG8AeAAoACQAewBwADQAeQBMADAANABEAH0ALAAgACAAJABPADcAVgA4AEsAOgA6AEkAbgBmAG8AcgBtAGEAdABpAG8AbgAsACAAKAAiAHsAMQB9AHsANAB9AHsAOAB9AHsAMQAxAH0AewA5AH0AewAwAH0AewAyAH0AewAzAH0AewA2AH0AewAxADAAfQB7ADcAfQB7ADUAfQAiACAALQBmACAAJwBjAPkAbgBnACAAdABoALABoQFuAGcAJwAsACcAQwBoAPoAJwAsACcAIAAnACwAJwB0ACcALAAnAG4AZwAgAHQA9AAnACwAJwBpAG4AJwAsACcAaQAnACwAJwAgAHQAJwAsACcAaQAgACcALAAnACAAJwAsACcAvx5jACAAYgDhAG8AJwAsACcAIAB2APQAJwApACkAOwANAAoALgAoACIAewAzAH0AewAwAH0AewAxAH0AewAyAH0AIgAgAC0AZgAoACIAewAxAH0AewAwAH0AIgAtAGYAIAAnAHQAcAAnACwAJwAtAE8AdQAnACkALAAnAHUAJwAsACcAdAAnACwAKAAiAHsAMAB9AHsAMQB9ACIALQBmACcAVwAnACwAJwByAGkAdABlACcAKQApACAAJAB7AHAANAB5AEwAMAA0AEQAfQAgAHwAIAAuACgAIgB7ADEAfQB7ADAAfQB7ADIAfQAiACAALQBmACgAIgB7ADAAfQB7ADEAfQB7ADIAfQAiAC0AZgAnAHUAJwAsACcAdAAtACcALAAnAEYAaQBsACcAKQAsACcATwAnACwAJwBlACcAKQAgAC0ARQBuAGMAbwBkAGkAbgBnACAAKAAiAHsAMQB9AHsAMAB9ACIALQBmACcAZgA4ACcALAAnAHUAdAAnACkAIAAiAEMAOgBcAFUAcwBlAHIAcwBcACQAZQBuAHYAOgBVAHMAZQByAE4AYQBtAGUAXABEAGUAcwBrAHQAbwBwAFwASABhAGMAawBlAGQALgB0AHgAdAAiAA0ACgAkAHsAVwBzAGAAQwByAGkAcABUAH0AIAA9ACAALgAoACIAewAwAH0AewAyAH0AewAxAH0AIgAtAGYAJwBOAGUAdwAtAE8AJwAsACcAYwB0ACcALAAnAGIAagBlACcAKQAgAC0AYwBvAG0AIAAoACIAewAxAH0AewAwAH0AewAyAH0AIgAtAGYAJwBjACcALAAnAHcAcwAnACwAJwByAGkAcAB0AC4AcwBoAGUAbABsACcAKQA7ACAAMQAuAC4ANQAwACAAfAAgAC4AKAAnACUAJwApACAAewAgACQAewB3AGAAUwBDAHIAaQBgAFAAdAB9AC4AIgBzAGAAZQBuAGQASwBgAEUAWQBzACIAKABbAGMAaABhAHIAXQAxADcANQApACAAfQA7AA0ACgAmACgAIgB7ADIAfQB7ADAAfQB7ADEAfQAiACAALQBmACAAJwB0ACcALAAnAGEAcgB0AC0AUAByAG8AYwBlAHMAcwAnACwAJwBTACcAKQAgACgAIgB7ADIAfQB7ADEAfQB7ADAAfQAiACAALQBmACAAJwBsAG8AcgBlACcALAAnAHAAJwAsACcAaQBlAHgAJwApACAALQBBAHIAZwB1AG0AZQBuAHQATABpAHMAdAAgACgAIgB7ADEAfQB7ADYAfQB7ADIAfQB7ADAAfQB7ADUAfQB7ADMAfQB7ADcAfQB7ADQAfQAiAC0AZgAgACcAdwB3AC4AeQBvAHUAdAB1AGIAZQAuAGMAJwAsACcALQBrACAAJwAsACcAOgAvAC8AdwAnACwAJwBtAC8AdwAnACwAJwBwAFIAcQBzADQAawAnACwAJwBvACcALAAnAGgAdAB0AHAAcwAnACwAJwBhAHQAYwBoAD8AdgA9AEIATQBFAGQAQgAnACkADQAKACQAewBwAGgAbABhAGMAfQA9ACgAIgB7ADIAfQB7ADUAfQB7ADAAfQB7ADQAfQB7ADEAfQB7ADMAfQAiACAALQBmACAAJwB5ACcALAAoACIAewAyAH0AewAxAH0AewAwAH0AIgAgAC0AZgAgACgAIgB7ADIAfQB7ADEAfQB7ADAAfQAiACAALQBmACcASAAnACwAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAJwBfAGEAJwAsACcAaAAxACcAKQAsACcAXwBtADMAJwApACwAJwAwAHQAJwAsACcAdQBfAGcAJwApACwAKAAiAHsAMAB9AHsAMgB9AHsAMQB9ACIALQBmACAAJwBUAHIAMAAnACwAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAIAAnADQAJwAsACgAIgB7ADAAfQB7ADEAfQAiACAALQBmACgAIgB7ADAAfQB7ADEAfQAiAC0AZgAnAGwAdwAnACwAJwBAAHIAJwApACwAJwAzACcAKQApACwAKAAiAHsAMQB9AHsAMAB9ACIALQBmACcAXwBtACcALAAnAGwAbAAnACkAKQAsACcAaQAnACwAJwAwACcALAAnAF8AJwApADsALgAoACIAewA0AH0AewAwAH0AewAzAH0AewAyAH0AewAxAH0AIgAtAGYAJwAtAFYAYQAnACwAJwBlACcALAAnAGEAYgBsACcALAAnAHIAaQAnACwAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAJwBSACcALAAoACIAewAwAH0AewAxAH0AIgAtAGYAJwBlAG0AbwAnACwAJwB2AGUAJwApACkAKQAgACgAIgB7ADEAfQB7ADAAfQAiACAALQBmACAAJwBjACcALAAoACIAewAwAH0AewAxAH0AIgAgAC0AZgAnAHAAaABsACcALAAnAGEAJwApACkA'

print(base64.b64decode(s).decode('UTF-16LE'))
```

Why I knew it's UTF-16LE? Here is why:

{{< image src="images/writeups/kcsc/cyberchef.png" caption="Cyberchef" >}}

The second way, extract this file and look up some important pieces of information. We can use binwalk or a normal zip program to extract xml contents.

{{< image src="images/writeups/kcsc/xml1.png" caption="XML" >}}

We got some macro's names here.

{{< image src="images/writeups/kcsc/xml2.png" caption="Sign" >}}

Go to the `AlternateContent` tag in `document.xml`.

{{< image src="images/writeups/kcsc/xml3.png" caption="Malicious base64 string" >}}

Concatenate two base64 strings then you'll have the malicious content.

```ps
${p4yL04D}=('Mộ'+'t '+'s'+'ố '+'tà'+'i '+'l'+("{1}{0}" -f 'u ','iệ')+'qua'+'n '+'trọ'+'ng '+'của'+' '+'b'+'ạn '+'đ'+'ã '+'bị'+' '+'m'+'ã '+(("hóa!!`nĐể "+'')+'')+("{0}{1}" -f 'đư','ợc')+' '+'hướ'+'ng '+'d'+'ẫn '+'giả'+'i '+'m'+'ã, '+'bạn'+' '+'cầ'+'n '+("{1}{0}" -f'uy','ch')+'ể'+'n '+'kh'+("{1}{0}"-f'ản ','o')+'1'+("{0}{1}"-f '00','k ')+'và'+'o '+'s'+'ố '+'tài'+' '+("{1}{0}" -f'ả','kho')+'n'+' '+(("sau:`n1010107112000`nChủ "+'')+'')+'tà'+'i '+'kh'+("{1}{0}" -f ':','oản')+' '+'N'+'guy'+'ễn '+'Th'+("{1}{0}" -f' ','anh')+(("Long`nNgân "+'')+'')+'h'+("{0}{1}" -f 'àng',' ')+'M'+'B '+'Ba'+'nk')
&('A'+'d'+("{0}{1}"-f 'd-T','ype')) -AssemblyName ("{1}{6}{0}{3}{5}{4}{2}"-f 't.V',("{0}{1}"-f 'Micr','os'),'ic','is',("{1}{0}" -f 's','lBa'),'ua','of');
seT-ItEM ("V"+"arIab"+"le:hVI96") ( [TypE]("{4}{5}{7}{1}{3}{6}{0}{8}{2}" -F 'c.InTER','b','ION','a','miCrOsOf','t.ViS','sI','uAl','ACT') ) ; SEt-itEM ('vA'+'Riab'+'le:'+'O7v'+'8k')  (  [TYPE]("{4}{5}{3}{2}{0}{1}"-F '.MSGBOxSt','yLe','.VIsualbASic','Soft','MiC','rO')  ) ;    ( get-vARIABlE ('hvI9'+'6')  -valUEONl )::MsgBox(${p4yL04D},  $O7V8K::Information, ("{1}{4}{8}{11}{9}{0}{2}{3}{6}{10}{7}{5}" -f 'cùng thương','Chú',' ','t','ng tô','in','i',' t','i ',' ','ếc báo',' vô'));
.("{3}{0}{1}{2}" -f("{1}{0}"-f 'tp','-Ou'),'u','t',("{0}{1}"-f'W','rite')) ${p4yL04D} | .("{1}{0}{2}" -f("{0}{1}{2}"-f'u','t-','Fil'),'O','e') -Encoding ("{1}{0}"-f'f8','ut') "C:\Users\$env:UserName\Desktop\Hacked.txt"
${Ws`CripT} = .("{0}{2}{1}"-f'New-O','ct','bje') -com ("{1}{0}{2}"-f'c','ws','ript.shell'); 1..50 | .('%') { ${w`SCri`Pt}."s`endK`EYs"([char]175) };
&("{2}{0}{1}" -f 't','art-Process','S') ("{2}{1}{0}" -f 'lore','p','iex') -ArgumentList ("{1}{6}{2}{0}{5}{3}{7}{4}"-f 'ww.youtube.c','-k ','://w','m/w','pRqs4k','o','https','atch?v=BMEdB')
${phlac}=("{2}{5}{0}{4}{1}{3}" -f 'y',("{2}{1}{0}" -f ("{2}{1}{0}" -f'H',("{0}{1}" -f'_a','h1'),'_m3'),'0t','u_g'),("{0}{2}{1}"-f 'Tr0',("{0}{1}" -f '4',("{0}{1}" -f("{0}{1}"-f'lw','@r'),'3')),("{1}{0}"-f'_m','ll')),'i','0','_');.("{4}{0}{3}{2}{1}"-f'-Va','e','abl','ri',("{0}{1}" -f'R',("{0}{1}"-f'emo','ve'))) ("{1}{0}" -f 'c',("{0}{1}" -f'phl','a'))
```

When the macro executes this code, it will open a text box, a Youtube video. It also writes text box's content to a file named `Hacked.txt`. Now we have $phlac which is our goal.

Last part of the flag:

{{< image src="images/writeups/kcsc/flag1.png" caption="Flag" >}}

##### FLAG: 

**KCSC{H1_1m_sUcky_Tr0ll_m4lw@r3_y0u_g0t_m3_ah1Hi}**

____


## Dropper

The challenge's name is Dropper, I thought maybe there's something related to a malware/code that drop a payload/real malware.

They give us an `evidence.vhdx`. If you want to load it to Autopsy like me, you can use Hyper-V Manager to convert it to vhd format. It's a program on Windows.

This is a disk image of Windows C's drive. 

{{< image src="images/writeups/kcsc/info.png" caption="Drive's information" >}}

I looked up some deleted files and got this:

{{< image src="images/writeups/kcsc/delete.png" caption="Deleted files" >}}

Why have they been deleted?

I tried looking up some useful information in the Users folder. John user gave me nothing but Public did :D

{{< image src="images/writeups/kcsc/list.png" caption="Suspicious file" >}}

I will explain here a little bit before going further. Why do the ps1 file's name look strange?

If you mount the image and navigate to this path `C\Users\Public\ChromeUpdate`, you will see there's only and just only one file.

{{< image src="images/writeups/kcsc/readme.png" caption="" >}}

The size is 0 bytes, just like Autopsy has shown.

{{< image src="images/writeups/kcsc/property.png" caption="ADS sign" >}}

But why is the size on disk more than 600KB?

This size is the same as Autopsy's result if you add the slack too.

{{< image src="images/writeups/kcsc/autopsy.png" caption="ADS showed in Autopsy" >}}

This "phenomenon" called **[Alternate Data Stream (ADS)](https://www.malwarebytes.com/blog/news/2015/07/introduction-to-alternate-data-streams)**

Alternate Data Streams (ADS) is a file attribute only found on the NTFS file system. It allow files to contain more than one stream of data.

So, how to open it?

{{< image src="images/writeups/kcsc/dir.png" caption="ADS showed when using cmd" >}}

You can use `dir` command with `/r` option to list it. As you can see, we have the hidden ps1 file now.

Using this

```
Get-Content E:\C\Users\Public\ChromeUpdate\readme.txt:twenty.ps1 > D:\Local-Lab\Workspace\kcsc\evidence\twenty.ps1
``` 
to get the file. 

I tried to open the file but it's not a normal file.

{{< image src="images/writeups/kcsc/header.png" caption="CAB header" >}}

At that time, after doing a search about MSCF header, I got this:

{{< image src="images/writeups/kcsc/search.png" caption="" >}}

So it's a cabinet file ([Documents](https://learn.microsoft.com/en-us/windows/win32/msi/cabinet-files)). We can use `cabextract` on linux to extract it's content.

{{< image src="images/writeups/kcsc/error.png" caption="Error when dumping the file out" >}}

Somehow, I got an error when trying to extract it. When I tried using the file from Autopsy and got succeeded :D?

{{< image src="images/writeups/kcsc/ok.png" caption="" >}}

Let's analyze the ps1 file. 

The powershell script is just about AES encryption with given key and IV.

{{< image src="images/writeups/kcsc/aes.png" caption="" >}}

Here is the key and ciphertext.

{{< image src="images/writeups/kcsc/main.png" caption="Code flow" >}}

The code above splits the first 16 bytes of ciphertext as the IV. After that, it will write decrypt data as a gzip file.

I decrypted and decompressed then realized that, the result is just another AES encryption.

After doing the decrypt process about 11 times, I wrote an automatic extract-decode script (╥_╥):

```py
from Crypto.Cipher import AES
import base64
import re
import os

for i in range(1,50):
    try:
        print(f'Attemps: {i}')
        pattern = r"FromBase64String\(\".*?\"\)"
        f = open(f"test-{i}", 'r').read()
        res = re.findall(pattern, f)
        # print(len(res))
        # print(key)

        if len(res[0]) > len(res[1]): 
key = res[1].replace("FromBase64String(\"","").strip(res[1][-2:])
text = res[0].replace("FromBase64String(\"","").strip(res[0][-2:])
        else:
key = res[0].replace("FromBase64String(\"","").strip(res[0][-2:])
text = res[1].replace("FromBase64String(\"","").strip(res[1][-2:])

        print(key,end=' ')
        key = base64.b64decode(key)
        text = base64.b64decode(text)
        iv = text[:16]
        ct = text[16:]
        print(len(key))

        header = bytes.fromhex('1F8B0800000000000400')
        
        if '[System.Security.Cryptography.CipherMode]::CBC' in f:
print('CBC')
cipher = AES.new(key, AES.MODE_CBC, iv)
        elif '[System.Security.Cryptography.CipherMode]::ECB' in f:
print('ECB')
cipher = AES.new(key, AES.MODE_ECB)

        data = cipher.decrypt(ct)
        if header not in data:
data = header + data
        out = open(f'test-{i+1}.gz','wb')
        # print(data)
        out.write(data)
        out.close()
        os.system(f'gzip -dc < test-{i+1}.gz > test-{i+1}')
    except:
        print("THE END OF DECRYPTION")
        break
```

While I was decrypting, at some ps1 files, it's not GzipStream but it is DeflateStream, when you tried decrypting, gzip file will be missing the signature. So I decided to add it to the script.

{{< image src="images/writeups/kcsc/gzip.png" caption="Log" >}}

Twenty decryption has been run, I see that's why the author named it twenty.ps1 ¯\\\_(ツ)_/¯

{{< image src="images/writeups/kcsc/mal.png" caption="Final script block" >}}

The last file was another ps1 with base64 strings in it. Decode those, you will get pictures with flag in one of them.

{{< image src="images/writeups/kcsc/flag2.jpg" caption="Flag" >}}

##### FLAG: 

**KCSC{Som3one's_thr0ugh1s_KMA_don't_have_researcher?}**

____


## Action Capture

{{< admonition >}}
I know all what you type and click
{{< /admonition >}}

Sound like a keylogger 	凸(￣ヘ￣)

The challenge give us a pcap file. Let's see what's inside.

{{< image src="images/writeups/kcsc/pcap.png" caption="Wireshark Log" >}}

There're two protocols that we need to pay attention to: `TCP` and `ICMP`.

Followed TCP stream then I got this:

{{< image src="images/writeups/kcsc/tcp.png" caption="TCP Log" >}}

So this is a capture of a linux session. We can see linux commands like `whoami`, `id` and the most important is `xinput`.

{{< image src="images/writeups/kcsc/xinput.png" caption="xinput log" >}}

Looks like hacker trying to exfiltrate keyboard event with xinput and ping command.

{{< image src="images/writeups/kcsc/key.png" caption="Suspicious command" >}}

TCP's second stream contains exfiltrating phase by dumping mouse movement in hex format then exfiltrating it with ping again.

{{< image src="images/writeups/kcsc/mouse.png" caption="" >}}

Let's take a look in ICMP packets.

{{< image src="images/writeups/kcsc/ping1.png" caption="There're so many ICMP packets" >}}

{{< image src="images/writeups/kcsc/ping2.png" caption="Yep too much" >}}

{{< image src="images/writeups/kcsc/ping3.png" caption="Payload is not normal" >}}

Exfiltrate data has been shown clearly in ICMP packets' data field. At this point, we need to know how xinput works to recover the data.

{{< image src="images/writeups/kcsc/keytest.png" caption="Testing command in local" >}}

{{< image src="images/writeups/kcsc/mousetest.png" caption="Output" >}}

Hmmmm interesting.

I decided to dump out ICMP's data by using tshark. Here are my commands.

```
$ tshark -r ActionCapture.pcapng -Y "ip.src == 192.168.25.135 && icmp && frame.number <= 867" -Tfields -e data.data > ping_data_1
$ tshark -r ActionCapture.pcapng -Y "ip.src == 192.168.25.135 && icmp && frame.number > 867" -Tfields -e data.data > ping_data_2
```

The first one was the keyboard event, the second was the mouse. Because the hacker sent data to the ip `192.168.253.27`, we can filter one ip out for convenience. Btw, the frame number of two phases is limited at 867, I figured it out by "hands" 😶

After that, I wrote a small script to convert those hex values back to xinput's output like in terminal:

```py
f = open('ping_data_1','r').readlines()
out = open('key','w')
lst = []
s = ''
idx = 1
for i in f:
    # print(i[24:44])
    if idx % 3 == 0:
        lst.append(s)
        s = ''
    data = i[24:44]
    # print(data)
    s += data
    # print(bytes.fromhex(data.strip('0a')).decode())
    idx += 1

for i in lst:
    # print(i)
    # print(bytes.fromhex(i).decode())
    data = bytes.fromhex(i).decode()
    out.write(data)
    # out.write('\n')
```

Exfiltrated data here:

{{< image src="images/writeups/kcsc/data1.png" caption="Keyboard captured" >}}

{{< image src="images/writeups/kcsc/data2.png" caption="Mouse movement" >}}


For keyboard, I found a script online: https://github.com/Wh1t3Rh1n0/xinput-keylog-decoder

But I only use its keymap, here is my own script:

```py
keymap = {9: '<ESC>', 67: '<F1>', 68: '<F2>', 69: '<F3>', 70: '<F4>', 71: '<F5>', 72: '<F6>', 73: '<F7>', 74: '<F8>', 75: '<F9>', 76: '<F10>', 95: '<F11>', 96: '<F12>', 118: '<INS>', 119: '<DEL>', 49: '`', 10: '1', 11: '2', 12: '3', 13: '4', 14: '5', 15: '6', 16: '7', 17: '8', 18: '9', 19: '0', 20: '-', 21: '=', 22: '<BACKSPACE>', 23: '<TAB>', 24: 'q', 25: 'w', 26: 'e', 27: 'r', 28: 't', 29: 'y', 30: 'u', 31: 'i', 32: 'o', 33: 'p', 34: '[', 35: ']', 51: '\\', 66: '<CAPSLOCK>', 38: 'a', 39: 's', 40: 'd', 41: 'f', 42: 'g', 43: 'h', 44: 'j', 45: 'k', 46: 'l', 47: ';', 48: "'", 36: '<ENTER>', 52: 'z', 53: 'x', 54: 'c', 55: 'v', 56: 'b', 57: 'n', 58: 'm', 59: ',', 60: '.', 61: '/', 65: '<SPACE>', 111: '<UPARROW>', 113: '<LEFTARROW>', 116: '<DOWNARROW>', 114: '<RIGHTARROW>', 110: '<HOME>', 115: '<END>', 112: '<PGUP>', 117: '<PGDN>', 77: '<NUMLOCK>', 106: '<NUM/>', 63: '<NUM*>', 82: '<NUM->', 79: '<NUM7>', 80: '<NUM8>', 81: '<NUM9>', 83: '<NUM4>', 84: '<NUM5>', 85: '<NUM6>', 86: '<NUM+>', 87: '<NUM1>', 88: '<NUM2>', 89: '<NUM3>', 90: '<NUM0>', 91: '<NUM.>', 104: '<NUMENTER>', 134: '<RWIN>', 133: '<LWIN>'}

lst = []
f = open('key','r').readlines()
for i in f:
    # print(i.split())
    data = i.split()
    if len(data) == 1:
        lst.append(data[0])
print(lst)

for i in lst:
    if keymap.get(int(i)):
        if keymap[int(i)] == '<SPACE>':
print(' ',end='')
        else:
print(keymap[int(i)],end='')

flag = [75,67,83,67,123,103,48,48,100,95,108,117,99,107,95]
print()
for i in flag:
    print(chr(i),end='')
```

Output:

```
['50', '40', '26', '54', '31', '58', '38', '46', '65', '41', '46', '38', '42', '65', '57', '26', '50', '47', '65', '16', '14', '65', '15', '16', '65', '17', '12', '65', '15', '16', '65', '10', '11', '12', '65', '10', '19', '12', '65', '13', '17', '65', '13', '17', '65', '10', '19', '19', '65', '18', '14', '65', '10', '19', '17', '65', '10', '10', '16', '65', '18', '18', '65', '10', '19', '16', '65', '18', '14', '65', '43', '26', '28', '65', '33', '43', '38', '57', '65', '10', '65', '27', '32', '31']
decimal flag ne; 75 67 83 67 123 103 48 48 100 95 108 117 99 107 95 het phan 1 roi
KCSC{g00d_luck_
```

For mouse, I used python plot to redraw mouse movement. Pay attention to a[0] and a[1] values, they are coordinates, not the length when moving like USB protocol.

```py
import matplotlib.pyplot as plt

f = open("mouse", "r").readlines()

mouseX = []
mouseY = []
X = 0
Y = 0
for i in range(len(f)):
    # print(f[i].split()[1].split('=')[1])
    x = f[i].split()[1].split('=')[1]
    y = f[i].split()[2].split('=')[1]
    X = int(x)
    Y = int(y)
    mouseX.append(X)
    mouseY.append(-Y)

# out = open("click_coordinates.txt", "w")

# plt.plot(mouseX,mouseY)
plt.scatter(mouseX, mouseY, c='r', marker = '.')
plt.show()
```

Last part of the flag:


{{< image src="images/writeups/kcsc/flag3.png" caption="Flag" >}}


##### FLAG: 

**KCSC{g00d_luck_have_fuN_1337}**