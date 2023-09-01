---
weight: 5
title: "Discover injecting implant by using memory forensics technique - Project Redline"
date: 2023-07-17T17:55:28+08:00
lastmod: 2023-07-17T17:55:28+08:00
draft: false
author: "1259iknowthat"
description: "A Forensics challenge from HTB Business 2023"
images: []
resources:
- name: "featured-image"
  src: "featured-image.png"

tags: ["Forensics","C2 Analysis"]
categories: ["WriteUps"]

twemoji: false
lightgallery: true
---

A Forensics challenge from HTB Business 2023

<!--more-->

## Preface

A few days ago, I had a chance to participating in HTB Business and play some forensics challenges. The event's always suprising me with it's scenarios, this time is no exception.

{{< image src="images/writeups/redline-htb/chal.png" caption="Challenge" >}}


I've solved this challenge after the event LOL, quite disappointed 🥲.

## Overview

We have two artifacts, one is a packet capture, another is a memory dump.

{{< image src="images/writeups/redline-htb/dns.png" caption="Wireshark Log" >}}

The capture is full of DNS records so I guess this is some kind of DNS tunneling. Let's move on to the dump file.

We have the RAM captured of the victim's machine which was infected with malware. Here we got some informations about the operating system:

{{< image src="images/writeups/redline-htb/os.png" caption="Volatility info" >}}


## Identify the malware

Since we have not known where is the malware, we must look up it.

First thing we can do is scanning some running processes in the dump.

```
Volatility 3 Framework 2.4.2
Progress:  100.00               PDB scanning finished
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime

4       0       System  0xad81e4479040  152     -       N/A     False   2023-06-13 22:32:27.000000      N/A
* 408   4       smss.exe        0xad81e889e040  2       -       N/A     False   2023-06-13 22:32:27.000000      N/A
* 1684  4       MemCompression  0xad81ebd0e040  42      -       N/A     False   2023-06-13 12:32:33.000000      N/A
* 124   4       Registry        0xad81e45d0040  4       -       N/A     False   2023-06-13 22:32:23.000000      N/A
616     584     csrss.exe       0xad81ead340c0  12      -       1       False   2023-06-13 22:32:31.000000      N/A
696     584     winlogon.exe    0xad81ead66080  5       -       1       False   2023-06-13 22:32:31.000000      N/A
* 504   696     dwm.exe 0xad81eaf0a080  22      -       1       False   2023-06-13 22:32:31.000000      N/A
** 592  504     wininit.exe     0xad81ead2a080  2       -       0       False   2023-06-13 22:32:31.000000      N/A
*** 916 592     fontdrvhost.ex  0xad81eae1a140  5       -       0       False   2023-06-13 22:32:31.000000      N/A
*** 740 592     services.exe    0xad81ead23080  6       -       0       False   2023-06-13 22:32:31.000000      N/A
**** 1028       740     svchost.exe     0xad81eaf68240  57      -       0       False   2023-06-13 22:32:31.000000      N/A
***** 3184      1028    taskhostw.exe   0xad81ec75d080  10      -       1       False   2023-06-13 12:32:44.000000      N/A
***** 2620      1028    taskhostw.exe   0xad81ec0b02c0  6       -       0       False   2023-06-13 12:32:34.000000      N/A
****** 2976     2620    ngentask.exe    0xad81ec1d6300  5       -       0       True    2023-06-13 12:32:34.000000      N/A
******* 3032    2976    conhost.exe     0xad81ec1ef200  4       -       0       False   2023-06-13 12:32:34.000000      N/A
******* 788     2976    ngen.exe        0xad81ec3e3080  6       -       0       True    2023-06-13 12:32:35.000000      N/A
******** 2248   788     mscorsvw.exe    0xad81ea1d8080  10      -       0       True    2023-06-13 12:36:13.000000      N/A
****** 2992     2620    ngentask.exe    0xad81ec1e1340  12      -       0       False   2023-06-13 12:32:34.000000      N/A
******* 3000    2992    conhost.exe     0xad81ec1e2080  4       -       0       False   2023-06-13 12:32:34.000000      N/A
******* 6612    2992    ngen.exe        0xad81eaa26080  4       -       0       False   2023-06-13 12:35:55.000000      N/A
***** 3932      1028    sihost.exe      0xad81ec679080  12      -       1       False   2023-06-13 12:32:43.000000      N/A
**** 1924       740     svchost.exe     0xad81ebdf62c0  4       -       0       False   2023-06-13 12:32:33.000000      N/A
**** 2052       740     svchost.exe     0xad81ebe970c0  13      -       0       False   2023-06-13 12:32:33.000000      N/A
**** 4104       740     svchost.exe     0xad81ecaa2080  3       -       0       False   2023-06-13 12:32:50.000000      N/A
**** 1932       740     svchost.exe     0xad81ebdf42c0  3       -       0       False   2023-06-13 12:32:33.000000      N/A
**** 1168       740     upfc.exe        0xad81eafc0080  1       -       0       False   2023-06-13 22:32:31.000000      N/A
**** 1428       740     VBoxService.ex  0xad81ebc7a240  11      -       0       False   2023-06-13 22:32:31.000000      N/A
**** 1816       740     svchost.exe     0xad81ebdee0c0  11      -       0       False   2023-06-13 12:32:33.000000      N/A
***** 6108      1816    audiodg.exe     0xad81ec0c9080  4       -       0       False   2023-06-13 12:33:57.000000      N/A
**** 6012       740     SgrmBroker.exe  0xad81ebd39080  7       -       0       False   2023-06-13 12:34:34.000000      N/A
**** 1592       740     svchost.exe     0xad81ebcee280  16      -       0       False   2023-06-13 12:32:33.000000      N/A
***** 3132      1592    ctfmon.exe      0xad81ec754240  12      -       1       False   2023-06-13 12:32:44.000000      N/A
**** 2232       740     svchost.exe     0xad81ebea2080  12      -       0       False   2023-06-13 12:32:33.000000      N/A
**** 1212       740     svchost.exe     0xad81eafcc2c0  16      -       0       False   2023-06-13 22:32:31.000000      N/A
**** 5052       740     SecurityHealth  0xad81eaaf6080  27      -       0       False   2023-06-13 12:33:07.000000      N/A
**** 1220       740     svchost.exe     0xad81eafd92c0  8       -       0       False   2023-06-13 22:32:31.000000      N/A
**** 3780       740     svchost.exe     0xad81ea6e70c0  8       -       0       False   2023-06-13 12:34:34.000000      N/A
**** 4172       740     SearchIndexer.  0xad81ec4cf080  16      -       0       False   2023-06-13 12:32:53.000000      N/A
***** 6936      4172    SearchProtocol  0xad81ea5b8080  11      -       0       False   2023-06-13 12:35:29.000000      N/A
***** 4768      4172    SearchFilterHo  0xad81ed3cf340  6       -       0       False   2023-06-13 12:35:29.000000      N/A
**** 2256       740     MsMpEng.exe     0xad81ebf92340  12      -       0       False   2023-06-13 12:32:33.000000      N/A
**** 3924       740     svchost.exe     0xad81ec6782c0  7       -       1       False   2023-06-13 12:32:43.000000      N/A
**** 1240       740     svchost.exe     0xad81eafdc2c0  13      -       0       False   2023-06-13 22:32:31.000000      N/A
**** 604        740     svchost.exe     0xad81ea8aa080  15      -       0       False   2023-06-13 12:34:35.000000      N/A
**** 2784       740     svchost.exe     0xad81ec2f3080  6       -       0       False   2023-06-13 12:32:35.000000      N/A
**** 3424       740     TrustedInstall  0xad81ec4d0080  3       -       0       False   2023-06-13 12:32:37.000000      N/A
**** 1892       740     svchost.exe     0xad81ebd0b080  4       -       0       False   2023-06-13 12:32:33.000000      N/A
**** 2788       740     svchost.exe     0xad81ec12a240  24      -       0       False   2023-06-13 12:32:34.000000      N/A
**** 1004       740     svchost.exe     0xad81eaeab2c0  9       -       0       False   2023-06-13 22:32:31.000000      N/A
**** 4092       740     svchost.exe     0xad81ea5ba2c0  3       -       0       False   2023-06-13 12:33:54.000000      N/A
**** 880        740     svchost.exe     0xad81eade9240  18      -       0       False   2023-06-13 22:32:31.000000      N/A
***** 4608      880     SearchApp.exe   0xad81ecdcd080  32      -       1       False   2023-06-13 12:32:55.000000      N/A
***** 4800      880     RuntimeBroker.  0xad81ed0ec2c0  6       -       1       False   2023-06-13 12:32:55.000000      N/A
***** 4484      880     RuntimeBroker.  0xad81ecdce2c0  13      -       1       False   2023-06-13 12:32:55.000000      N/A
***** 1284      880     RuntimeBroker.  0xad81ea9a2080  8       -       1       False   2023-06-13 12:33:05.000000      N/A
***** 5916      880     MoUsoCoreWorke  0xad81ea8ac080  12      -       0       False   2023-06-13 12:34:35.000000      N/A
***** 4328      880     StartMenuExper  0xad81ec5bb080  6       -       1       False   2023-06-13 12:32:54.000000      N/A
***** 5896      880     ApplicationFra  0xad81ecaa4080  3       -       1       False   2023-06-13 12:33:52.000000      N/A
***** 3468      880     TiWorker.exe    0xad81eac45080  2       -       0       False   2023-06-13 12:32:38.000000      N/A
***** 6840      880     RuntimeBroker.  0xad81ea6d6300  6       -       1       False   2023-06-13 12:34:57.000000      N/A
***** 5944      880     TextInputHost.  0xad81ea7b2300  12      -       1       False   2023-06-13 12:35:17.000000      N/A
***** 6420      880     WmiPrvSE.exe    0xad81eaf08080  5       -       0       False   2023-06-13 12:34:44.000000      N/A
***** 4984      880     WmiPrvSE.exe    0xad81e856c2c0  9       -       0       False   2023-06-13 12:33:53.000000      N/A
***** 2748      880     smartscreen.ex  0xad81ea9a4080  15      -       1       False   2023-06-13 12:33:07.000000      N/A
***** 6716      880     ShellExperienc  0xad81ec5be080  17      -       1       False   2023-06-13 12:34:56.000000      N/A
**** 1652       740     spoolsv.exe     0xad81ebdfa0c0  8       -       0       False   2023-06-13 12:32:33.000000      N/A
**** 3316       740     svchost.exe     0xad81ebd3a080  3       -       1       False   2023-06-13 12:32:48.000000      N/A
**** 6264       740     svchost.exe     0xad81ea62e240  6       -       0       False   2023-06-13 12:34:38.000000      N/A
**** 1916       740     svchost.exe     0xad81ebdf22c0  16      -       0       False   2023-06-13 12:32:33.000000      N/A
*** 748 592     lsass.exe       0xad81ead81300  9       -       0       False   2023-06-13 22:32:31.000000      N/A
** 516  504     csrss.exe       0xad81e860c080  11      -       0       False   2023-06-13 22:32:31.000000      N/A
* 908   696     fontdrvhost.ex  0xad81eae1c140  5       -       1       False   2023-06-13 22:32:31.000000      N/A
* 3420  696     userinit.exe    0xad81ec59d300  0       -       1       False   2023-06-13 12:32:46.000000      2023-06-13 12:33:15.000000
** 2952 3420    explorer.exe    0xad81ebd3b300  65      -       1       False   2023-06-13 12:32:46.000000      N/A
*** 2672        2952    SecurityHealth  0xad81ea2ec340  5       -       1       False   2023-06-13 12:33:07.000000      N/A
*** 5736        2952    vlc.exe 0xad81e832c080  5       -       1       False   2023-06-13 12:35:57.000000      N/A
*** 5200        2952    msedge.exe      0xad81ed0f8080  54      -       1       False   2023-06-13 12:33:08.000000      N/A
**** 928        5200    msedge.exe      0xad81ecfab340  0       -       1       False   2023-06-13 12:35:16.000000      2023-06-13 12:35:44.000000
**** 6016       5200    msedge.exe      0xad81ed0fa080  20      -       1       False   2023-06-13 12:36:00.000000      N/A
**** 6884       5200    msedge.exe      0xad81ece6f080  14      -       1       False   2023-06-13 12:35:30.000000      N/A
**** 3880       5200    msedge.exe      0xad81eaa29080  16      -       1       False   2023-06-13 12:35:24.000000      N/A
**** 5228       5200    msedge.exe      0xad81ea62b0c0  9       -       1       False   2023-06-13 12:33:08.000000      N/A
**** 1052       5200    msedge.exe      0xad81eaa1f080  16      -       1       False   2023-06-13 12:35:24.000000      N/A
**** 5424       5200    msedge.exe      0xad81ecec90c0  11      -       1       False   2023-06-13 12:33:09.000000      N/A
**** 5396       5200    msedge.exe      0xad81ea7c70c0  21      -       1       False   2023-06-13 12:33:09.000000      N/A
**** 5404       5200    msedge.exe      0xad81ea69a0c0  17      -       1       False   2023-06-13 12:33:09.000000      N/A
*** 5124        2952    VBoxTray.exe    0xad81ea2ee080  13      -       1       False   2023-06-13 12:33:08.000000      N/A
```

Hmmmm, there's no suspicious process until now. If `vlc.exe` look sus to you, it's just VLC Media Player, a normal program. Let's see if we can get something with cmdline and network.

```
Volatility 3 Framework 2.4.2
Progress:  100.00               PDB scanning finished
PID     Process Args

4       System  Required memory at 0x20 is not valid (process exited?)
124     Registry        Required memory at 0x20 is not valid (process exited?)
408     smss.exe        \SystemRoot\System32\smss.exe
516     csrss.exe       %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
592     wininit.exe     wininit.exe
616     csrss.exe       %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
696     winlogon.exe    winlogon.exe
740     services.exe    C:\Windows\system32\services.exe
748     lsass.exe       C:\Windows\system32\lsass.exe
880     svchost.exe     C:\Windows\system32\svchost.exe -k DcomLaunch -p
908     fontdrvhost.ex  "fontdrvhost.exe"
916     fontdrvhost.ex  "fontdrvhost.exe"
1004    svchost.exe     C:\Windows\system32\svchost.exe -k RPCSS -p
504     dwm.exe "dwm.exe"
1028    svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs -p
1168    upfc.exe        C:\Windows\System32\Upfc.exe /launchtype boot /cv 51tlxXBJ6UifoEf6UqyGXA.0
1212    svchost.exe     C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork -p
1220    svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
1240    svchost.exe     C:\Windows\system32\svchost.exe -k LocalService -p
1428    VBoxService.ex  C:\Windows\System32\VBoxService.exe
1592    svchost.exe     C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p
1684    MemCompression  Required memory at 0x20 is not valid (process exited?)
1816    svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
1892    svchost.exe     C:\Windows\system32\svchost.exe -k appmodel -p
1924    svchost.exe     C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p
1916    svchost.exe     C:\Windows\system32\svchost.exe -k NetworkService -p
1932    svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
1652    spoolsv.exe     C:\Windows\System32\spoolsv.exe
2052    svchost.exe     C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p
2232    svchost.exe     C:\Windows\System32\svchost.exe -k utcsvc -p
2256    MsMpEng.exe     "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.23050.3-0\MsMpEng.exe"
2620    taskhostw.exe   taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}
2788    svchost.exe     C:\Windows\system32\svchost.exe -k wsappx -p
2976    ngentask.exe    "C:\Windows\Microsoft.NET\Framework\v4.0.30319\NGenTask.exe" /RuntimeWide /Critical /StopEvent:980
2992    ngentask.exe    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\NGenTask.exe" /RuntimeWide /Critical /StopEvent:992
3000    conhost.exe     \??\C:\Windows\system32\conhost.exe 0x4
3032    conhost.exe     \??\C:\Windows\system32\conhost.exe 0x4
2784    svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted
788     ngen.exe        "C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe" ExecuteQueuedItems 2 /LegacyServiceBehavior
3424    TrustedInstall  C:\Windows\servicing\TrustedInstaller.exe
3468    TiWorker.exe    C:\Windows\winsxs\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.19041.2905_none_7dd39c4c7cb9dfa0\TiWorker.exe -Embedding
3924    svchost.exe     C:\Windows\system32\svchost.exe -k UnistackSvcGroup
3932    sihost.exe      sihost.exe
3184    taskhostw.exe   taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}
3132    ctfmon.exe      "ctfmon.exe"
3420    userinit.exe    Required memory at 0x7fa4c87020 is not valid (process exited?)
2952    explorer.exe    C:\Windows\Explorer.EXE
3316    svchost.exe     C:\Windows\system32\svchost.exe -k ClipboardSvcGroup -p
4104    svchost.exe     C:\Windows\System32\svchost.exe -k swprv
4172    SearchIndexer.  C:\Windows\system32\SearchIndexer.exe /Embedding
4328    StartMenuExper  "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca
4484    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
4608    SearchApp.exe   "C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe" -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca
4800    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
1284    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
2748    smartscreen.ex  C:\Windows\System32\smartscreen.exe -Embedding
2672    SecurityHealth  "C:\Windows\System32\SecurityHealthSystray.exe"
5052    SecurityHealth  C:\Windows\system32\SecurityHealthService.exe
5124    VBoxTray.exe    "C:\Windows\System32\VBoxTray.exe"
5200    msedge.exe      "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start /prefetch:5
5228    msedge.exe      "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=crashpad-handler "--user-data-dir=C:\Users\rsteven\AppData\Local\Microsoft\Edge\User Data" /prefetch:7 --monitor-self-annotation=ptype=crashpad-handler "--database=C:\Users\rsteven\AppData\Local\Microsoft\Edge\User Data\Crashpad" --annotation=IsOfficialBuild=1 --annotation=channel= --annotation=chromium-version=114.0.5735.91 "--annotation=exe=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --annotation=plat=Win64 "--annotation=prod=Microsoft Edge" --annotation=ver=114.0.1823.37 --initial-client-data=0x164,0x168,0x16c,0x140,0x178,0x7ffed62c4210,0x7ffed62c4220,0x7ffed62c4230
5396    msedge.exe      "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=gpu-process --gpu-preferences=WAAAAAAAAADgAAAMAAAAAAAAAAAAAAAAAABgAAAAAAA4AAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAYAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAIAAAAAAAAAA== --mojo-platform-channel-handle=1784 --field-trial-handle=1972,i,6865033189529423298,9519355283962404745,262144 /prefetch:2
5404    msedge.exe      "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --mojo-platform-channel-handle=2352 --field-trial-handle=1972,i,6865033189529423298,9519355283962404745,262144 /prefetch:3
5424    msedge.exe      "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=utility --utility-sub-type=storage.mojom.StorageService --lang=en-US --service-sandbox-type=service --mojo-platform-channel-handle=2432 --field-trial-handle=1972,i,6865033189529423298,9519355283962404745,262144 /prefetch:8
5896    ApplicationFra  C:\Windows\system32\ApplicationFrameHost.exe -Embedding
4984    WmiPrvSE.exe    C:\Windows\system32\wbem\wmiprvse.exe
4092    svchost.exe     C:\Windows\system32\svchost.exe -k WbioSvcGroup
6108    audiodg.exe     C:\Windows\system32\AUDIODG.EXE 0x51c
3780    svchost.exe     C:\Windows\System32\svchost.exe -k NetworkService -p
6012    SgrmBroker.exe  C:\Windows\system32\SgrmBroker.exe
5916    MoUsoCoreWorke  C:\Windows\System32\mousocoreworker.exe -Embedding
604     svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
6264    svchost.exe     C:\Windows\System32\svchost.exe -k netsvcs -p
6420    WmiPrvSE.exe    C:\Windows\system32\wbem\wmiprvse.exe
6716    ShellExperienc  "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe" -ServerName:App.AppXtk181tbxbce2qsex02s8tw7hfxa9xb3t.mca
6840    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
928     msedge.exe      Required memory at 0x9397928020 is not valid (process exited?)
5944    TextInputHost.  "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe" -ServerName:InputApp.AppXjd5de1g66v206tj52m9d0dtpppx4cgpn.mca
3880    msedge.exe      "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=renderer --disable-gpu-compositing --lang=en-US --js-flags=--ms-user-locale= --device-scale-factor=1 --num-raster-threads=3 --enable-main-frame-before-activation --renderer-client-id=17 --time-ticks-at-unix-epoch=-1686659544494870 --launch-time-ticks=180344912 --mojo-platform-channel-handle=4528 --field-trial-handle=1972,i,6865033189529423298,9519355283962404745,262144 /prefetch:1
1052    msedge.exe      "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=renderer --disable-gpu-compositing --lang=en-US --js-flags=--ms-user-locale= --device-scale-factor=1 --num-raster-threads=3 --enable-main-frame-before-activation --renderer-client-id=18 --time-ticks-at-unix-epoch=-1686659544494870 --launch-time-ticks=180356326 --mojo-platform-channel-handle=5072 --field-trial-handle=1972,i,6865033189529423298,9519355283962404745,262144 /prefetch:1
6936    SearchProtocol  "C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe2_ Global\UsGthrCtrlFltPipeMssGthrPipe2 1 -2147483646 "Software\Microsoft\Windows Search" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" "C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc" "DownLevelDaemon"
4768    SearchFilterHo  "C:\Windows\system32\SearchFilterHost.exe" 0 796 800 808 8192 804 780
6884    msedge.exe      "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=renderer --disable-gpu-compositing --lang=en-US --js-flags=--ms-user-locale= --device-scale-factor=1 --num-raster-threads=3 --enable-main-frame-before-activation --renderer-client-id=22 --time-ticks-at-unix-epoch=-1686659544494870 --launch-time-ticks=185473805 --mojo-platform-channel-handle=5984 --field-trial-handle=1972,i,6865033189529423298,9519355283962404745,262144 /prefetch:1
6612    ngen.exe        "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe" install "System.Xml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" /NoDependencies /noroot /version:v4.0.30319 /LegacyServiceBehavior
5736    vlc.exe "C:\Users\rsteven\Desktop\vlc-win32\vlc.exe"
6016    msedge.exe      "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=renderer --instant-process --disable-gpu-compositing --lang=en-US --js-flags=--ms-user-locale= --device-scale-factor=1 --num-raster-threads=3 --enable-main-frame-before-activation --renderer-client-id=26 --time-ticks-at-unix-epoch=-1686659544494870 --launch-time-ticks=216196232 --mojo-platform-channel-handle=5684 --field-trial-handle=1972,i,6865033189529423298,9519355283962404745,262144 /prefetch:1
2248    mscorsvw.exe    C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe -StartupEvent 330 -InterruptEvent 0 -NGENProcess 354 -Pipe 2dc -Comment "NGen Worker Process"
```

Nothing interesting with command line.

```
0xad81e44e0320  TCPv4   10.0.2.15       49830   173.222.107.76  443     ESTABLISHED     5404    msedge.exe      2023-06-13 12:36:17.000000
0xad81e832d010  TCPv4   10.0.2.15       49828   152.199.19.161  80      ESTABLISHED     5404    msedge.exe      2023-06-13 12:36:09.000000
0xad81ea5c0010  TCPv4   10.0.2.15       49815   93.184.221.240  80      ESTABLISHED     1916    svchost.exe     2023-06-13 12:35:41.000000
0xad81eafc24a0  TCPv4   10.0.2.15       49829   204.79.197.239  443     ESTABLISHED     5404    msedge.exe      2023-06-13 12:36:09.000000
0xad81ecee44a0  TCPv4   10.0.2.15       49793   62.210.246.226  443     ESTABLISHED     5404    msedge.exe      2023-06-13 12:35:26.000000
0xad81ed3b6930  TCPv4   10.0.2.15       49817   192.229.221.95  80      ESTABLISHED     2748    smartscreen.ex  2023-06-13 12:35:56.000000
```

Okay, looks like we got some connections to some websites through Microsoft Edge. I wonder what the website will be. We can look up browsing history by finding browser's cache files, in this case, these files will be in this path: `C:\Users\xxxx\AppData\Local\Microsoft\Edge\User Data\Default\Cache`.

Here are the files we need to dump out:

```
0xad81ec9a4980  \Users\rsteven\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\index    216
0xad81ecb284d0  \Users\rsteven\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\data_3   216
0xad81ecb29150  \Users\rsteven\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\data_0   216
0xad81ecb29ab0  \Users\rsteven\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\data_2   216
0xad81ecb2a5a0  \Users\rsteven\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\data_1   216
0xad81ecb3f590  \Users\rsteven\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\data_1   216
0xad81ecb3fa40  \Users\rsteven\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\data_0   216
0xad81ecb40080  \Users\rsteven\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\data_2   216
0xad81ecb403a0  \Users\rsteven\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\data_3   216
```

The `data_1` file gave me a really interesting result:

{{< image src="images/writeups/redline-htb/http.png" caption="Suspicious URLs" >}}


These are extremely strange urls which has been accessed by the victim. I guess this is how the malware got into the machine because this is maybe a phishing website. Back to the existing files we caught in the memory, we got these:

```
0xad81eac310c0  \Users\rsteven\Desktop\vlc-win32\libvlc.dll     216
0xad81ec6b5b00  \Users\rsteven\Desktop\vlc-win32\vlc.exe        216
0xad81ecda9910  \Users\rsteven\Desktop\vlc-win32\vlc.exe        216
0xad81ecdb33c0  \Users\rsteven\Desktop\vlc-win32        216
0xad81ed453600  \Users\rsteven\Desktop\vlc-win32\libvlccore.dll 216
0xad81ed454410  \Users\rsteven\Desktop\vlc-win32        216
0xad81ed4545a0  \Users\rsteven\Desktop\vlc-win32\ffmpeg.dll     216
0xad81ed454730  \Users\rsteven\Desktop\vlc-win32        216
```

These files were downloaded by this url: `http://get.video1an.org/vlc/3.0.18/win64/vlc-3.0.18-win64.zip`

We can actually view it's hex values in the memory:

{{< image src="images/writeups/redline-htb/hex1.png" caption="Zip values in dump" >}}

But unfortunately, the zip was truncated so we can't recover it. The zip file also contains a suspicious file.

{{< image src="images/writeups/redline-htb/hex2.png" caption="codex.dat" >}}

`codex.dat` file disappeared in the memory, quite strange isn't it?

Back to three dlls remain in the dump, I think one of them is the malware. Let's check it out by uploading to VirusTotal.

Here we go:

{{< image src="images/writeups/redline-htb/vt1.png" caption="VirusTotal's result" >}}


Nice! Now we've known where the fun begins.

## Analysis

The dll was built by C/C++ so we need to use a disassembler like IDA to view it's content.

We can start at the main function:

{{< image src="images/writeups/redline-htb/ida1.png" caption="Malware's Main function" >}}

On the other hand, I've got the real dll from the official VLC Media Player.

{{< image src="images/writeups/redline-htb/ida2.png" caption="VLC valid function" >}}

I think you've seen the difference.

Jumping to `StartAddress` function, we got this:

{{< image src="images/writeups/redline-htb/ida3.png" caption="Suspicious behaviour" >}}

The dll load `codex.dat` file and then inject it to RuntimeBroker.exe process. Very cool! But, the file was not in the memory, how do we extract it? We've known that the payload/shellcode has been injected to RuntimeBroker process, so maybe the dump can catch it and we can extract it by dumping the process' memory.

Let's run `malfind` plugin to verify if our prediction was corrected.

```
4484    RuntimeBroker.  0x29e784d0000   0x29e7949afff   VadS    PAGE_EXECUTE_READWRITE  4043    1       Disabled
e8 46 ab fc 00 eb 00 41 .F.....A
b0 b9 48 c7 c1 29 ab fc ..H..)..
00 4c 8d 1d 09 00 00 00 .L......
45 30 04 0b 45 02 04 0b E0..E...
e2 f6 55 48 89 e5 48 83 ..UH..H.
ec 7f 48 89 ec 5d e8 00 ..H..]..
00 00 00 59 49 89 c8 ba ...YI...
6b c4 22 b3 49 81 c0 14 k.".I...
0x29e784d0000:  call    0x29e7949ab4b
0x29e784d0005:  jmp     0x29e784d0007
0x29e784d0007:  mov     r8b, 0xb9
0x29e784d000a:  mov     rcx, 0xfcab29
0x29e784d0011:  lea     r11, [rip + 9]
0x29e784d0018:  xor     byte ptr [r11 + rcx], r8b
0x29e784d001c:  add     r8b, byte ptr [r11 + rcx]
0x29e784d0020:  loop    0x29e784d0018
0x29e784d0022:  push    rbp
0x29e784d0023:  mov     rbp, rsp
0x29e784d0026:  sub     rsp, 0x7f
0x29e784d002a:  mov     rsp, rbp
0x29e784d002d:  pop     rbp
0x29e784d002e:  call    0x29e784d0033
0x29e784d0033:  pop     rcx
0x29e784d0034:  mov     r8, rcx
0x29e784d0037:  mov     edx, 0xb322c46b
```

Ohhh, we have a RWX page with this pid `4484`, nice!

Why was it PAGE_EXECUTE_READWRITE? When an executable is loaded into memory, no section of it has permission of both READ and WRITE. This is only suspicious because there are legitimate reasons to do this, so do the shellcode/payload.

How to recover the payload? Just dump it out.

From there, I decided to use `binwalk` to go through the dump to find something strange.

```
$ binwalk pid.4484.vad.0x29e784d0000-0x29e7949afff.dmp

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
2887          0xB47           Microsoft executable, portable (PE)
2265956       0x229364        gzip compressed data, from FAT filesystem (MS-DOS, OS/2, NT), last modified: 2047-05-10 21:19:34 (bogus date)
2953786       0x2D123A        bix header, header size: 64 bytes, header CRC: 0xF1084, created: 1989-03-10 17:08:16, image size: 987523 bytes, Data Address: 0x90000000, Entry Point: 0xF108424, data CRC: 0x28010000, OS: pSOS, CPU: AVR, image name: ""
5394256       0x524F50        bix header, header size: 64 bytes, header CRC: 0x488B84, created: 1989-06-21 20:56:32, image size: 4753840 bytes, Data Address: 0x80000000, Entry Point: 0x4C898088, data CRC: 0x83, image name: ""
9974187       0x9831AB        gzip compressed data, last modified: 1970-01-01 18:12:15 (bogus date)
9974223       0x9831CF        EBML file
9974343       0x983247        GIF image data, version "87a", 18759
9974351       0x98324F        GIF image data, version "89a",
10221578      0x9BF80A        LZMA compressed data, properties: 0x6D, dictionary size: 0 bytes, uncompressed size: 79 bytes
11168098      0xAA6962        LZMA compressed data, properties: 0x6D, dictionary size: 0 bytes, uncompressed size: 32 bytes
11830077      0xB4833D        LANCOM OEM file
12144353      0xB94EE1        VxWorks symbol table, big endian, first entry: [type: function, code address: 0x2001800, symbol address: 0x8245]
12917959      0xC51CC7        SHA256 hash constants, little endian
12917975      0xC51CD7        SHA256 hash constants, little endian
14021542      0xD5F3A6        mcrypt 2.2 encrypted data, algorithm: blowfish-192, mode: ECB, keymode: SHA-1 hash
16176086      0xF6D3D6        mcrypt 2.2 encrypted data, algorithm: blowfish-448, mode: CBC, keymode: MD5 hash
16176150      0xF6D416        mcrypt 2.2 encrypted data, algorithm: blowfish-448, mode: CBC, keymode: 4bit
```

We got an executable at `0xB47` offset. Let's check it in hex view in case the binwalk could be mismatched.

{{< image src="images/writeups/redline-htb/hex3.png" caption="Hex values" >}}

Okay... We do have an actual executable in this dump. And again, after extracting it, we upload to VirusTotal.

{{< image src="images/writeups/redline-htb/vt2.png" caption="VirusTotal's result" >}}


Seems like this is Sliver's implant. Now we move on to the final stage.

## Decode, Decrypt, Dedge

We have known this is Sliver's implant so we can get its source code on [github](https://github.com/BishopFox/sliver) instead of reversing the whole binary 🥶.

I also found this [blog](https://www.immersivelabs.com/blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide/) which is useful for us to decrypt the traffic.


### Traffic

Back to the packet capture, we have full of DNS records, many of them point to a suspicious domain - the attacker's domain.

{{< image src="images/writeups/redline-htb/dns2.png" caption="DNS exfiltration" >}}

Looking at the the DNS query's name, we can easily see the format of it: `<encoded_data>.v10.events.data.microsoftcloudservices.com`

The encoded data seems like in baseXX format but we can't decode it, including base64, base32, base58 and so on. Turns out, the implant is using a different baseXX-encoding based on the original one. The above blog has mentioned this:

{{< image src="images/writeups/redline-htb/blog1.png" caption="Different base encoding" >}}

By looking at the source code, we can see that the implant does not stop at base32 and base58, but it also use it own base64 implementation.

{{< image src="images/writeups/redline-htb/source1.png" caption="Source code" >}}

I think this is the update version of the blog's dictionaries:

{{< image src="images/writeups/redline-htb/update.png" caption="Updated" >}}

Mapping those characters back to the right one is not enough. We still cannot decode the string after that job so I believe that the implant has encrypted it before. I found this function in the source, it used chacha encryption:

{{< image src="images/writeups/redline-htb/source2.png" caption="Encryption" >}}

At this point, decrypting the traffic is quite challenging for us since the key for the decryption is not in the packet. I decided to digging the blog deeper.

{{< image src="images/writeups/redline-htb/blog2.png" caption="Recover session key" >}}

As it said, the key we need is in the memory. Now we have enough informations to begin the decryption. I was too lazy to write scripts so I found a tool can do this job well: https://github.com/Immersive-Labs-Sec/SliverC2-Forensics

It is the blog's author's tool LMAO 😂

### Decrypt

First thing to do is extracting the encoded data from pcap.

{{< image src="images/writeups/redline-htb/tool.png" caption="Data" >}}

We can use tshark for this thing:

{{< image src="images/writeups/redline-htb/tshark.png" caption="tshark could do the job well" >}}

To remove duplicated DNS query's name, you can filter the pcap to one IP.

{{< image src="images/writeups/redline-htb/decrypt1.png" caption="Bruteforcing the key" >}}

From here, we have known the right key was used so just use that key to speed up the decrypion instead of brute forcing.

{{< image src="images/writeups/redline-htb/decrypt2.png" caption="Final data" >}}

We got PDF's password here: `$_Ultr4_s3cur3_P@55W0rD!!_$`

And here is a gzip file contains a PDF inside it:

{{< image src="images/writeups/redline-htb/decrypt3.png" caption="Gzip file here guys" >}}

Extract, decompress and open with the given password:

{{< image src="images/writeups/redline-htb/flag.png" caption="Flag is in the pdf" >}}

Thank you for reading this.

Happy Hunting 😍