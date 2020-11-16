 
<p align="center">
  <h1>
   OSfooler-NG
   <img align="right" width="256" src="https://github.com/moonbaseDelta/OSfooler-ng/blob/master/logo.png">
  </h1> 
 </p> 
<br> 
 
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Version: 1.0b](https://img.shields.io/badge/version-1.0b-blue.svg)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-blue.svg)](https://GitHub.com/segofensiva/OSfooler-ng/graphs/commit-activity)
 
# Synopsis
 
This is a fork of [segofensiva/OSfooler-ng](https://github.com/segofensiva/OSfooler-ng). 

Main reason of that fork is that original project seems to be an abandoned proof-of-concept, but the project is still valuable. 
By now the main difference is the change of Python2's nfqueue (NetfilterQueue) version from 0.5 to 0.8.1 for the sake of run the OSfooler-ng on different distros, not just deb-based. 

Yes, it's Python2 yet. If you know how to properly move NetfilterQueue to Python 3.6+ and can test the project nicely and in short time - [your help is welcome](https://github.com/moonbaseDelta/OSfooler-ng/issues/1).

Original author's project presentation can be found on Youtube [https://www.youtube.com/watch?v=psxxT00KavM](https://www.youtube.com/watch?v=psxxT00KavM). You may also find a few articles about OSfooler-NG. This version is a remake of 2014' OSfooler made by the same person, but the old one is archived and should be concidered lost.
The whole topic of OS-fingerprinting and it's defeating is rather obscure.  
OSfooler-NG is working, but not yet perfect even against nmap and p0f. Any futher help, even testcases, and so is highly needed.

By now it's been tested fine on Arch and CentOS7, CentOS8, Ubuntu 18.04. 
 


**You may help hugely by trying this on different distros and submit issues.**
By now it's been tested fine on Arch and CentOS7.



# Installation


To get this version, just use git:
```
$ git clone https://github.com/moonbaseDelta/OSfooler-ng.git
``` 
You need to install python NetfilterQueue (v0.8.1 or more) linux package. Download from [PyPi](https://pypi.org/project/NetfilterQueue/0.8.1/):
``` 
$ wget https://files.pythonhosted.org/packages/39/c4/8f73f70442aa4094b3c37876c96cddad2c3e74c058f6cd9cb017d37ffac0/NetfilterQueue-0.8.1.tar.gz
$ tar -xzf NetfilterQueue-0.8.1.tar.gz
$ cd NetfilterQueue-0.8.1
$ sudo python2 setup.py install
```
or try: 
```
$ pip2 install NetfilterQueue
```

Install OSfooler-ng in the standard way:
```
$ sudo python2 setup.py install
```

There're also [instructions](https://github.com/moonbaseDelta/OSfooler-ng/wiki/Installation) for some specific distros in project's Wiki.




## Known issues 
No such device IO error (error code 19): 
  * By default program uses 'eth0' interface that may not be even exist on your machine
  * Find your main TCP/IP interface (you can find it by 'ip a' command)
  * Run OSfooler-ng commands with:
```
$ <osfooler command> -i 'YOURINTERFACE'
```


# Usage
## Active Fingerprinting: nmap
To get the full list of OS to emulate, just use the flag '-n':
```
$ osfooler-ng -n
 [+] Please, select nmap OS to emulate
    + "2N Helios IP VoIP doorbell"
    + "2Wire BT2700HG-V ADSL modem"
    + "2Wire 1701HG wireless ADSL modem"
    [...]
    + "ZyXEL Prestige 660HW-61 ADSL router (ZyNOS 3.40)"
    + "ZyXEL Prestige 660HW-D1 wireless ADSL router"
    + "ZyXEL ZyWALL 2 Plus firewall"
```

To emulate an specific OS, just use the flag '-o' with the OS you want to emulate:
```
$ osfooler-ng -m "Sony Ericsson W705 or W715 Walkman mobile phone"
 [+] Mutating to nmap:
      Fingerprint Sony Ericsson W705 or W715 Walkman mobile phone
      Class Sony Ericsson | embedded || phone
      CPE cpe:/h:sonyericsson:w705
      CPE cpe:/h:sonyericsson:w715
      SEQ(CI=RD%II=I)
      OPS(R=N)
      WIN(R=N)
      ECN(R=N)
      T1(R=N)
      T2(R=Y%DF=N%T=3B-45%TG=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
      T3(R=N)
      T4(R=Y%DF=N%T=3B-45%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
      T5(R=Y%DF=N%T=3B-45%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
      T6(R=Y%DF=N%T=3B-45%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
      T7(R=Y%DF=N%T=3B-45%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
      U1(DF=N%T=3B-45%TG=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
      IE(DFI=N%T=3B-45%TG=40%CD=S)
 [+] Activating queues
      [->] Process-1: nmap packet processor
```

## Passive Fingerprinting: p0f v2
To get the full list of OS to emulate, just use the flag '-l':
```
$ osfooler-ng -p 
Please, select p0f OS Genre and Details
        OS Genre="AIX" Details="4.3"
        OS Genre="AIX" Details="4.3.2 and earlier"
        OS Genre="AIX" Details="4.3.3-5.2 (1)"
        [...]
        OS Genre="-*NMAP" Details="OS detection probe w/flags (3)"
        OS Genre="-*NMAP" Details="OS detection probe w/flags (4)"
        OS Genre="-*NAST" Details="syn scan"
```

To emulate any p0f OS, just use the flag '-o' with the OS Genre. This will choose the main OS and custom version will be randomly loaded when a SYN packet is detected. For example:
```
$ osfooler-ng -o "PalmOS"
 [+] Mutating to p0f:
      WWW:S9|TTL:255|D:0|SS:44|OOO:M536|QQ:.|OS:PalmOS|DETAILS:Tungsten T3/C
      WWW:S5|TTL:255|D:0|SS:44|OOO:M536|QQ:.|OS:PalmOS|DETAILS:3/4
      WWW:S4|TTL:255|D:0|SS:44|OOO:M536|QQ:.|OS:PalmOS|DETAILS:3.5
      WWW:2948|TTL:255|D:0|SS:44|OOO:M536|QQ:.|OS:PalmOS|DETAILS:3.5.3 (Handera)
      WWW:S29|TTL:255|D:0|SS:44|OOO:M536|QQ:.|OS:PalmOS|DETAILS:5.0
      WWW:16384|TTL:255|D:0|SS:44|OOO:M1398|QQ:.|OS:PalmOS|DETAILS:5.2 (Clie)
      WWW:S14|TTL:255|D:0|SS:44|OOO:M1350|QQ:.|OS:PalmOS|DETAILS:5.2.1 (Treo)
      WWW:16384|TTL:255|D:0|SS:44|OOO:M1400|QQ:.|OS:PalmOS|DETAILS:5.2 (Sony)
 [+] Activating queues
      [->] Process-1: p0f packet processor
```
 
 You can also emulate the full p0f OS, using '-' with the OS Genre and '-d' with custom details:
 ```
 $ osfooler-ng -o "Windows" -d "XP bare-bone"
  [+] Mutating to p0f:
      WWW:65520|TTL:128|D:1|SS:48|OOO:M*,N,N,S|QQ:.|OS:Windows|DETAILS:XP bare-bone
 [+] Activating queues
      [->] Process-1: p0f packet processor
 ```

## Active and Passive Fingerprinting: nmap & p0f
OSfooler-ng is also capable os emulating both OS to defeat nmap and p0f. Just combine the parameters above:
```
$ osfooler-ng -m "Microsoft Windows 2000 SP4" -o "Windows" -d "2000 SP4"
 [+] Mutating to nmap:
      Fingerprint Microsoft Windows 2000 SP4
      Class Microsoft | Windows | 2000 | general purpose
      CPE cpe:/o:microsoft:windows_2000::sp4
      SEQ(SP=7C-86%GCD=1-6%ISR=95-9F%TI=I%II=I%SS=O|S%TS=0)
      OPS(O1=NNT11|M5B4NW0NNT00NNS%O2=NNT11|M5B4NW0NNT00NNS%O3=NNT11|M5B4NW0NNT00%O4=NNT11|M5B4NW0NNT00NNS%O5=NNT11|M5B4NW0NNT00NNS%O6=NNT11|M5B4NNT00NNS)
      WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFFF)
      ECN(R=Y%DF=N%T=7B-85%TG=80%W=0%O=%CC=N%Q=U)
      T1(R=Y%DF=Y%T=7B-85%TG=80%S=O%A=O|S+%F=A|AS%RD=0%Q=|U)
      T2(R=Y%DF=N%T=7B-85%TG=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=U)
      T3(R=Y%DF=N%T=7B-85%TG=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=U)
      T4(R=Y%DF=N%T=7B-85%TG=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=U)
      T5(R=Y%DF=N%T=7B-85%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=U)
      T6(R=Y%DF=N%T=7B-85%TG=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=U)
      T7(R=Y%DF=N%T=7B-85%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=U)
      U1(DF=N%T=7B-85%TG=80%IPL=38%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
      IE(DFI=S%T=7B-85%TG=80%CD=Z)
 [+] Mutating to p0f:
      WWW:40320|TTL:128|D:1|SS:48|OOO:M*,N,N,S|QQ:.|OS:Windows|DETAILS:2000 SP4
 [+] Activating queues
      [->] Process-1: nmap packet processor
      [->] Process-2: p0f packet processor
```

## Searching for Operating Systems
You can search inside nmap/p0f database for a specific OS, instead of getting the whole list. Just use the flag '-s' and enter the keyword you want to search for (case insensitive). You'll get any match found, and if it belongs to nmap or p0f databases:
```
$ osfooler-ng -s playstation
 [+] Searching databases for: 'playstation'
      [nmap] "Sony Playstation 4 or FreeBSD 10.2-RELEASE"
      [nmap] "Sony PlayStation 2 game console test kit 2.2.1"
      [nmap] "Sony PlayStation 3 game console"
      [nmap] "Sony PlayStation 3 game console test kit"
      [nmap] "Sony PlayStation 2 game console"
      [p0f] OS: "Sony" DETAILS: "Playstation 2 (SOCOM?)"
```

## Update nmap database
Use the flag '-u' to check if there's a new version of nmap's database avaiable and to download it
```
$ osfooler-ng -u
 [+] Checking nmap database... latest!
```

## Custom flags
There are other interesting flags:
  * '-v': Show info about every modified packet
  * '-i <interface>': Choose network interface (eth0 by default)
  * '-V': Show OSfooler-ng banner and current version installed

# Authors
* **[Jaime Sánchez](https://www.seguridadofensiva.com) ([@segofensiva)](https://twitter.com/segofensiva)**

# License

This project is licensed under the The **GNU General Public License v3.0** - see the [LICENSE.md](LICENSE.md) file for details

# Acknowledgments

* https://github.com/segofensiva/OSfooler-ng#acknowledgments
