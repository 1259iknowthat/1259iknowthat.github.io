---
weight: 5
title: "ISITDTU CTF Quals 2022"
date: 2022-09-05T17:55:28+08:00
lastmod: 2022-05-13T17:55:28+08:00
draft: false
author: "tr4c3datr4il"
description: "Full misc challenges write-ups from ISITDTU qualifier 2022 🚩"
images: []
resources:
- name: "featured-image"
  src: "featured-image.jpg"

tags: ["Misc"]
categories: ["WriteUps"]

twemoji: false
lightgallery: true
---

Full misc challenges write-ups from ISITDTU qualifier 2022 🚩

<!--more-->

## Welcome

This is the second time that I have participated in a Vietnamese's CTF event. This time I played with my team and we had tried our best. I have learnt a lot too.

There're so much things we have been through but I can't tell you all. Let's begin with the first challenge!

{{< admonition >}}
Find me and say a greeting in Discord
{{< /admonition >}}

After joining the server, I looked up every places, every corners then I saw those emojis.

![](https://user-images.githubusercontent.com/89141562/201653459-09f62f6f-f057-4791-bc11-f167423aec6a.png)

I decided to "zoom" it out in the browser. Here's the result:

![](https://user-images.githubusercontent.com/89141562/201653735-ad088f05-b7af-457a-b318-6ac333692de1.png)

##### FLAG: 

**ISITDTU{Welcome_to_ISITDTU-CTF-2022_You_find_me}**

____

## Find

{{< admonition >}}
A friend of mine went on a trip in November 1st and sent me a picture of the landscape there, but when I asked, he didn't remember. Please help me find the place in the photo. Format flag: ISITDTU{LOCATION-CITY}
- Hint: a famous place in Tuyen Quang
{{< /admonition >}}

Here's the picture which were given to us:

![Suspicious Picture](https://user-images.githubusercontent.com/89141562/201653844-2940ffb7-3013-43aa-b46f-6935db394e7f.jpg)

Before the hint was released, it was too hard to tell where this was. But it became so easy with the hint lmao.

Opening google map, searching for Tuyen Quang in Viet Nam then we had this:

![](https://user-images.githubusercontent.com/89141562/201654224-c6dcdc58-b0f6-4684-9af0-6a7547fdefec.png)

As you can see, there is just one big river in Tuyen Quang so that I decided to use Google Street View to look up where was the riverbank in the picture. Suddenly I had this:

![](https://user-images.githubusercontent.com/89141562/201654937-d2d5f591-9c1d-4dad-838a-8dc8e98cfbe9.png)

But it's not correct. We need to move right a little bit! Then I saw Den Ha is the nearest location which I need, here is the result:

![This is the destination](https://user-images.githubusercontent.com/89141562/201655087-3c718881-206f-45c0-bfbf-ffe1ef9520f5.png)

So I guess the place is Den Ha in Tuyen Quang. Bang! Correct answer!

##### FLAG: 

**ISITDTU{DENHA_TUYENQUANG}**

____

## The Fear Of Sherlock

{{< admonition >}}
Pablo Sherlock planned to show his new painting to the public. However, an incident occurred. The painting was actually stolen and posted for sale on social media by someone named Johny Panker. He also said that he could prove the authorship of the painting. During our investigation, we noticed that his account looks like a clone. So I need your help to find out the true identity of this thief.
{{< /admonition >}}

This challenge cost me about 4-5 hours to solve it. Damn I'm still noob at this XD

So what we have here? Two names: Pablo Sherlock and Johny Panker. I had looked up Sherlock in the internet but had nothing. Johny Panker was different, he had a Facebook profile:

![Suspect's profile on Facebook](https://user-images.githubusercontent.com/89141562/201655209-61ce18fa-df06-4a6a-8709-59b2dc4f051d.png)

Look like we are in the right way. After sitting for a few hours, I downloaded the "dragon" picture and extract it's metadata. Found something interesting:

![Suspicious pbashicture on his post](https://user-images.githubusercontent.com/89141562/201655259-ec083bb5-6355-4fc2-b00f-66bdd1284b74.png)

```
┌──(kali㉿devilmachine)-[/mnt/d/WSL_LAB/Workplace/isitdtu]
└─$ exiftool wtf.jpg
ExifTool Version Number         : 12.49
File Name                       : wtf.jpg
Directory                       : .
File Size                       : 83 kB
File Modification Date/Time     : 2022:11:13 00:29:45+07:00
File Access Date/Time           : 2022:11:14 17:37:52+07:00
File Inode Change Date/Time     : 2022:11:13 21:05:35+07:00
File Permissions                : -rwxrwxrwx
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 96
Y Resolution                    : 96
Exif Byte Order                 : Big-endian (Motorola, MM)
Artist                          : bodramsilvader
Profile CMM Type                : Little CMS
...
```

Have you seen it? If not, just look at the `Artist` field, we have bodramsilvader as username, very suspicious. I used `sherlock` on it but got nothing. Then I found him on Linkedin (by accident) :D

![Suspect's Linkedin profile](https://user-images.githubusercontent.com/89141562/201655318-197aa9e0-2f1e-4e31-90f0-ae3cc28debcc.png)

Viewing HTB's certificate gave me the flag:

![](https://user-images.githubusercontent.com/89141562/201655387-8de9e8d7-f341-493b-ab68-a8619cec18a1.png)

![](https://user-images.githubusercontent.com/89141562/201655410-1138b0f2-8d65-4ed7-875d-6490ee19447a.png)

##### FLAG: 

**ISITDTU{L1nk3d1n_4nT!_Sh3RL0ck}**

____

## Malicious Project (The Fear Of Sherlock 2)

{{< admonition >}}
After finding out the true identity of Johnny Panker. We discovered that he was also planning to develop a malicious project. We need to find out his whereabouts and arrest him ASAP.
{{< /admonition >}}

Let's continue the story with this challenge. So, we have his Linkedin profile. I decided to stalk on his activities and noticed he has a Gitlab project :DD. That's interesting...

![](https://user-images.githubusercontent.com/89141562/201655496-a5d7822d-f265-44a9-b30d-8adbaf09057d.png)

Stay focuse on the picture, you can see there's an ID in it! Nice, now we can get the project by this `https://gitlab.com/projects/40976143`. You can read it from [here](https://docs.gitlab.com/ee/user/project/working_with_projects.html)

![](https://user-images.githubusercontent.com/89141562/201655572-42c20a55-47e7-4b8e-a961-fa12dad74295.png)

There was a link in readme file. Opened it up then we had this sheet:

![](https://user-images.githubusercontent.com/89141562/201655622-23118cbe-2bb3-4e05-9887-b1e525eaec1f.png)

I decided to download it and unhide the Contact field because it was one of the hidden fields.

![](https://user-images.githubusercontent.com/89141562/201655691-1ed141f9-de89-4e32-afdd-a48cee68d508.png)

Got the encoded flag, put it in [basecrack](https://basecrack.herokuapp.com/)

![](https://user-images.githubusercontent.com/89141562/201655755-2fda51e7-c178-4dbf-bb48-762fd7f6a304.png)

![](https://user-images.githubusercontent.com/89141562/201655803-fe9a707f-d105-4b90-9020-0ac59fa89e42.png)

##### FLAG: 

**ISITDTU{Ju5t_90_&_U_w1lL_C0m3}**

____

## T1M3

{{< admonition >}}
An anonymous Script Kiddie recently used many hacking tools to break into different websites to sabotage it and today my server was his victim. Please help me analyze what data he got.
{{< /admonition >}}

Opened up the pcap file, I noticed there was some strange URL. Filtered the file:

![](https://user-images.githubusercontent.com/89141562/201655968-028f067c-f256-4048-9555-34905d13c3e3.png)

Decode those URLs:

```
...
/dashboard.php?id=1 AND (SELECT 2460 FROM (SELECT(SLEEP(2-(IF(ORD(MID((SELECT IFNULL(CAST(username AS NCHAR),0x20) FROM myDB.users ORDER BY id LIMIT 4,1),3,1))!=111,0,2)))))pFUv)

/dashboard.php?id=1 AND (SELECT 2460 FROM (SELECT(SLEEP(2-(IF(ORD(MID((SELECT IFNULL(CAST(username AS NCHAR),0x20) FROM myDB.users ORDER BY id LIMIT 4,1),4,1))>48,0,2)))))pFUv)

/dashboard.php?id=1 AND (SELECT 2460 FROM (SELECT(SLEEP(2-(IF(ORD(MID((SELECT IFNULL(CAST(username AS NCHAR),0x20) FROM myDB.users ORDER BY id LIMIT 4,1),4,1))>1,0,2)))))pFUv)
```

There will be nothing suspicious if you take a quick look, but there is! Can you see those operations like `>, =, !=`? That's the thing we need. There're a lots of `>` or `=`, but `!=` is less. I decided to extract the contents following after this operation by that simple script.

```py
from urllib.parse import unquote
lst = []
f = open('test.txt', 'r').readlines()
for i in f:
    decode = unquote(i)
    if '!=' not in decode:
        data = decode.strip(decode)
    else:
        data = decode.split("!=")[-1].split(",")[0]
    if data.isnumeric():
        lst.append(data)
for i in lst:
    print(chr(int(i)), end="")
```

Tada ~

```
┌──(kali㉿devilmachine)-[/mnt/d/WSL_LAB/Workplace/isitdtu]
└─$ python script.py
3innformation_schemaperformance_schemamyDB1users04emailidpasswordusername5admin@uwu.com1admin@adminadminnguyendt@uwu.com2ISITDTU{W3llC0M3_T0_ISITDTU_2@22}to^happy@uwu.com3abc#123sangngocjorosensei@uwu.com4123321yugeiego@uwu.com528102003ego
```

##### FLAG: 

**ISITDTU{W3llC0M3_T0_ISITDTU_2@22}**

____

## DCeased XXIV

{{< admonition >}}
A virus killed my flag file, my python3.8 was only abled to save a part of it, please help me with your powerful python3.10
{{< /admonition >}}

![out](https://user-images.githubusercontent.com/89141562/201656169-f9f65ae8-4bbc-4068-8da7-53ef4ac92b84.png)

![part](https://user-images.githubusercontent.com/89141562/201656188-4ac88b4e-d299-4ea6-9dba-f697566ed084.png)

Final challenge, we got three files, one is final output of xor function, one is umcompleted part, one is encode fucntion file. Let's take a look at the python file:

```py
from PIL import Image
import random, time

def xor(a):
	return a[0] ^ a[1]

def xor_tuple(a, b):
	return tuple(i for i in map(xor, zip(*[a, b])))

def rgba2int(rgba: tuple):
	ret = 0
	for i in range(3, -1, -1):
		ret += rgba[i] << 8*(3 - i)
	return ret

def int2rgba(n):
	r, g, b, a = tuple([(n >> 8*i) & 0xff for i in range(3, -1, -1)])
	return (r, g, b, a)

img = Image.open('flag.png')

random.seed(time.time())

px = img.load()
x_len, y_len = img.size

new = Image.new('RGBA', (x_len, y_len), 'white')
px1 = new.load()

for y in range(y_len):
	for x in range(x_len):
		rand = random.getrandbits(32)
		rr, rg, rb, ra = int2rgba(rand)
		r, g, b, a = px[x, y]
		new_pix = xor_tuple((rr, rg, rb, ra), (r, g, b, a))
		px1[x, y] = new_pix

new.save('out.png')
```

From what I have learnt in a few hours, I wrote decode function:

```py
from PIL import Image
from randcrack import RandCrack
import random, time

def xor(a):
	return a[0] ^ a[1]

def xor_tuple(a, b):
	return tuple(i for i in map(xor, zip(*[a, b])))

def rgba2int(rgba: tuple):
	ret = 0
	for i in range(3, -1, -1):
		ret += rgba[i] << 8*(3 - i)
	return ret

def int2rgba(n):
	r, g, b, a = tuple([(n >> 8*i) & 0xff for i in range(3, -1, -1)])
	return (r, g, b, a)

random.seed(time.time())
rc = RandCrack()

out = Image.open('out.png') 
px_out = out.load() 
x_len, y_len = out.size 

flag = Image.new('RGBA', (x_len, y_len), 'white') 
px_flag = flag.load() 

part = Image.open('part.png')
px_part = part.load()

### Encode function:
# for y in range(y_len):
# 	for x in range(x_len):
#       # random a 32bit number
# 		rand = random.getrandbits(32) 
#       # convert it to r g b a values
# 		rr, rg, rb, ra = int2rgba(rand) 
#       # get r g b a values from flag image
# 		r, g, b, a = px[x, y] 
#       # xor r g b a values of flag image and random number
# 		new_pix = xor_tuple((rr, rg, rb, ra), (r, g, b, a)) 
# 		px1[x, y] = new_pix

for y in range(1):
	for x in range(0, 624):
		out_pix = px_out[x, y] 
		p1, p2, p3, p4 = px_part[x, y]
		s1, s2, s3, s4 = xor_tuple((out_pix), (p1, p2, p3, p4))
		test = s1, s2, s3, s4
		sample = rgba2int(test)
		rc.submit(sample)
		# print(sample)

### Check if those samples were correct
# lst = [1197901675,1631070050,461952881,695734403,1693692895,4283640773,2928387107,1928785835,3552053743,2537002435,47055549,2410773111,3036268006,1962088228,2622062508,3360313555,205185067,406621298,2822302039,195284038,1298505483,2974534449,1629527062,619152213,1443903758,4049396867,3461833431,544549987,173819087,3786990645,3220134908,1491372565,3960311345,1047841558,1148930451,913878785,235507096,3922721545,2956212125,1610654756,3240738596,2434114801,34872189,1210047227,2669923634,380992960,2110488274,1045117861,808900620,454604348,3612919969,2230622426,2729156078,259287658,2142030491,1219593728,1493280361,2927857529,2922770127,2577449564,1525463036,157122178,506948529,446178433,2394768460,779128425,672032810,533977385,414962736,3981494362,1932243016,2409206457,1396272772,2576029195,772103975,1204578821,2065476586,4026836526,2060181467,2446460588,853525408,1674279148,304666292,2836240319,1622211602,1026745654,3726043738,2939198009,1339345948,1180294413,1761125033,2639571804,1051273632,3324619002,2589868806,3196507220,1954281734,1616506922,1577685310,2980610704,3352184374,1823911760,1377784818,89826055,2117428061,3373623653,2130469573,752946063,780493667,1725659398,2472677468,1052074410,3578794441,139618247,1642190679,2059380021,417310436,2691248768,3975470242,3582189373,890230304,2914513654,2968689448,1305029369,3855144801,1435421174,2637313297,234961193,2835260522,1969153811,2639643700,2783650693,2816649027,3554397743,1224827490,3909243423,3163393688,244974913,1497895053,56780133,1057139306,150426172,1304832831,3191944216,3746244152,85512312,834391124,3126402617,1057694560,4152312075,1158274452,2677869702,2611763288,835930153,3271477550,199750445,3450097949,2178872853,3823328224,415494687,1478397033,721801976,531707720,402867627,405319513,3511270949,429636866,3256553860,4150161636,3874192473,3901737677,1736964486,1210479325,3031195868,3917412367,2547498244,1785795606,2285983140,2021550311,3271887948,1226069800,428710888,2340751775,1396002921,2938349586,3676373106,3396556031,2062397285,1299248961,125248035,1306895079,1490378110,3883610224,2074165723,2730591598,1079229318,401777246,1473146486,4053808406,4097922264,888477111,3585352486,2906324330,3295439814,3970008325,862975177,649974625,1272417617,254461703,828526695,2417880465,1872849225,3802467093,2713985259,2333287875,4243427501,3794956766,3476221975,1428892057,3585416377,867415123,695915171,1303752249,3085861646,1460034589,3942338113,534598595,4269987837,184857188,842996418,2627616963,1231475824,3476518073,3792644963,2332371989,3566350699,2931387111,1572603146,2143586167,1875628280,2781224553,3798229007,3918463929,317860522,4140811732,3632348312,2711857184,1285293794,3314050387,1876829746,1691543761,2526744135,2285968241,86977380,4193337632,1876970006,343666181,460383579,945046048,1632339968,2517095095,1311349646,2917318819,2157596586,2143554770,3471793639,49630996,2221938087,1973558154,1348285551,4076646445,374418982,3723342009,3631138514,4035935620,2120836005,1678669952,1294074787,3407890148,3345101209,1551571940,3707148113,1514873478,2550361490,1258655641,1440585693,3994317499,3204116869,1727453618,3522915217,749154403,4185425141,2715584904,978669746,1651458762,875666211,3159119515,2625337807,3582702957,3219827611,2851984821,3015287583,4132235787,1467242109,4138452023,1508297810,604592281,1045363589,1982669767,2018139502,86359391,2961171356,2903801898,3264495031,2692978745,4258106241,1506175289,323605680,2525840197,1053810801,1817779970,2575174493,2322126075,1206443808,3200465753,1179680704,1376314741,4142549257,4202636989,48126944,8348061,39445885,952152397,775219078,1555267560,2790080301,3846414281,1785514891,960311277,4050575676,3660059856,2638029648,1147418082,3122341802,3181563800,1374234603,712952404,489692254,2029458528,45477460,2871955363,1864753560,172163517,816789025,1562117711,749332335,3934048842,1568367037,3669505701,2775596767,3712630481,2306530571,3114372742,2035587511,1412651876,750157643,261014642,4020762037,2157337738,992770884,2072118037,1658334477,1124986104,3763515122,3440921226,3489146177,3312546428,1034062716,2175105267,2521508504,3897247650,3192414298,971508708,4005582261,3212567327,3415394423,25016049,1935626469,5818529,979758218,2919291067,713296232,3742072567,2774706536,2198743922,3932049610,1237706724,1737850026,294689586,1791645824,2245330737,2663703836,312269168,422548647,1890392728,4234049017,4019183864,1545076206,2817594002,2748949892,347655619,3065787052,1669389959,2830222943,1158063427,2957145905,2856390804,2904413466,3962997553,1908502552,3184728940,2503088565,605979412,851766053,1301293785,645205486,3297059065,2143776630,3532651402,1617235574,2369633942,775894437,1231301337,7868638,3269564840,1507538449,712482807,4218610552,2005830934,649075654,1843794059,52517954,2475859459,55354848,2344921527,2987187018,202541876,437673235,2649942616,3465790233,1483458592,8661155,4030915029,2850743486,1189102174,4158176256,3116611839,1191234238,3698711412,636551911,1418711093,1954338196,2792708438,191661069,3004510594,58480938,2316702907,10501015,3107683680,1973492648,3496029093,3298806507,4289027810,1735145861,1074993587,1330432781,742612659,1741343512,489610335,3527293050,4029094926,2111374478,2384112311,949942774,2395577555,516932451,755513088,3564121388,671361408,961661168,3838875954,1752265192,2154335975,2770884576,1574797719,1766758623,834037135,1986602583,596668944,639727931,320076941,2434070119,1850697793,2831259751,2645950823,3399479223,811261837,3303469418,955254248,1206942635,4183040821,627491463,2659400352,3560713874,3347856825,2763932422,4159354472,1665823031,1656914565,2978248789,4162229091,2687703980,415738259,2092548204,1541609186,4146856517,2451096236,2944483703,3792881913,1238325378,4110768619,909752588,1137054598,2855343777,1843752018,2011020806,899124438,192537054,2415562941,1072235640,2188380023,3299625520,1844403569,2097120108,578229175,1911772133,2903388428,1922089261,2003112354,867287211,1514057605,1078960302,1678814145,596712353,2255965580,2697335991,1873656396,2662915605,1595549560,242445176,872531386,2616078268,3815273216,2776965571,2859307430,2528812013,1156856913,127169256,3767258170,3164904762,239064171,2812265916,1037871158,2310882438,3613472962,2776929277,126525991,1776535282,3105425570,3541021682,2505278579,808620610,1265993888,1049113515,140282394,1222385768,20124513,2537889233,1756989257,753664539,2359669694,2622348347,612173961,3866765659,660619413,3375430861,1157492614,2572693308,152656776,160878342,2305903795,3182951469,3780257576,2260618664,2824769527,2755128110,98211055,453533164,462471313,3142794694,3983681124,1995037341,2242571042,997724124,3370563512,2086384465,1434058275,3476868376,791347289,3825677772,1727558202,1171966408,2830195772,2913122596]
# for y in range(1):
# 	for x in range(0, 624):
# 		rand = lst[x]
# 		rr, rg, rb, ra = int2rgba(rand)
# 		flag_pix = px_out[x, y]
# 		r, g, b, a = xor_tuple((flag_pix), (rr, rg, rb, ra))
# 		px_flag[x, y] = r, g, b, a

for y in range(0, y_len):
	for x in range(624 if y == 0 else 0, x_len):
		rand = rc.predict_randrange(0, 4294967295)
		rr, rg, rb, ra = int2rgba(rand)
		flag_pix = px_out[x, y]
		r, g, b, a = xor_tuple((flag_pix), (rr, rg, rb, ra))
		px_flag[x, y] = r, g, b, a
		
flag.save('flag.png')
```

Quick explaining:

So we have a xor function, int to rgba values, rgba values to int numbers, open file, etc:

```py
def xor(a):
	return a[0] ^ a[1]

def xor_tuple(a, b):
	return tuple(i for i in map(xor, zip(*[a, b])))

def rgba2int(rgba: tuple):
	ret = 0
	for i in range(3, -1, -1):
		ret += rgba[i] << 8*(3 - i)
	return ret

def int2rgba(n):
	r, g, b, a = tuple([(n >> 8*i) & 0xff for i in range(3, -1, -1)])
	return (r, g, b, a)

img = Image.open('flag.png')

random.seed(time.time())

px = img.load()
x_len, y_len = img.size

new = Image.new('RGBA', (x_len, y_len), 'white')
px1 = new.load()
```

But that's not so important, they are just for encoding image by xor-ing the "flag" pixel value with a random pixel value (RGBA obviously). If you know xor function, this should be easy. If we have a ^ b = c, we will also have this c ^ b = a, or c ^ a = b! So all we have to do, was just reverse the code xd. Let's focus on the next function:

```py
for y in range(y_len):
	for x in range(x_len):
		rand = random.getrandbits(32)
		rr, rg, rb, ra = int2rgba(rand)
		r, g, b, a = px[x, y]
		new_pix = xor_tuple((rr, rg, rb, ra), (r, g, b, a))
		px1[x, y] = new_pix
```

As you can see, at every pixel of the image (we have 720x720), it will take a RANDOM 32 bit number to generate a rgba value. So in order to crack this, we will use [`randcrack`](https://github.com/tna0y/Python-random-module-cracker) - a python module that support us to do this thing :D

Here is the result:

![flag](https://user-images.githubusercontent.com/89141562/201656265-f4020f01-06f6-4075-b0e3-0c5bce2b55d2.png)

##### FLAG: 

**ISITDTU{DC_DC34s3d_h4v3_y0u_r34d?}**