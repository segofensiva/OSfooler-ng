<p align="center">
<img width="256" src="https://i.ibb.co/DLnNK9J/268497.png">
</p>
<br>

# OSfooler-NG
 [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Version: 1.0](https://img.shields.io/badge/version-1.0-blue.svg)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-blue.svg)](https://GitHub.com/segofensiva/OSfooler-ng/graphs/commit-activity)

An outsider has the capability to discover general information, such as which operating system a host is running, by searching for default stack parameters, ambiguities in IETF RFCs or non-compliant TCP/IP implementations in responses to malformed requests. By pinpointing the exact OS of a host, an attacker can launch an educated and precise attack against a target machine.

There are lot of reasons to hide your OS to the entire world:
 * Revealing your OS makes things easier to find and successfully run an exploit against any of your devices.
 * Having and unpatched or antique OS version is not very convenient for your company prestige. Imagine that your company is a bank and some users notice that you are running an unpatched box. They won't trust you any longer! In addition, these kind of 'bad' news are always sent to the public opinion.
 * Knowing your OS can also become more dangerous, because people can guess which applications are you running in that OS (data inference). For example if your system is a MS Windows, and you are running a database, it's highly likely that you are running MS-SQL.
 * It could be convenient for other software companies, to offer you a new OS environment (because they know which you are running).
 * And finally, privacy; nobody needs to know the systems you've got running.

OSfooler was presented at Blackhat Arsenal 2013. It was built on NFQUEUE, an iptables/ip6tables target which delegate the decision on packets to a userspace. It transparently intercepted all traffic that your box was sending in order to camouflage and modify in real time the flags in TCP/IP packets that discover your system.

OSfooler-NG has been complete rewriten from the ground up, being highly portable, more efficient and combining all known techniques to detect and defeat at the same time:
 * Active remote OS fingerprinting: like Nmap
 * Passive remote OS fingeprinting: like p0f v2
 * Commercial engines like Sourcefire’s FireSiGHT OS fingerprinting

Some additional features are:
 * No need for kernel modification or patches
 * Simple user interface and several logging features
 * Transparent for users, internal process and services
 * Detecting and defeating mode: active, passive & combined
 * Will emulate any OS
 * Capable of handling updated nmap and p0f v2 fingerprint database
 * Undetectable for the attacker

# Install
To get the latest versions, with bugfixes and new features, but maybe not as stable, use the the Github repository:
```
$ git clone https://github.com/segofensiva/OSfooler-ng.git
```

You need to install python-nfqueue (v0.5-1build2) linux package. Download from [Ubuntu Packages](https://packages.ubuntu.com/xenial/python-nfqueue):
```
$ wget http://mirrors.kernel.org/ubuntu/pool/universe/n/nfqueue-bindings/python-nfqueue_0.5-1build2_amd64.deb
$ dpkg -i python-nfqueue_0.5-1build2_amd64.deb
```

Install OSfooler-ng in the standard way:
```
$ sudo python setup.py install
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

* [Defcon China](https://defcon.org/html/dc-china-1/dc-cn-1-index.html), for leting me show this tool on [Demo Labs](https://defcon.org/html/dc-china-1/dc-cn-1-demolabs.html#segofensiva)
* All those people who have worked and released software on OS fingerprinting (attack and defense), specially [nmap](https://nmap.org/) & [p0f](lcamtuf.coredump.cx/), but also Xprobe, IP Personality etc.
* OSfooler-ng makes use of the [Scapy Project](https://scapy.net/) and [The netfilter.org "libnetfilter_queue" project](https://netfilter.org/projects/libnetfilter_queue/)
