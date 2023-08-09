# Awesome Volatility [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> A collection of interesting resources for Volatility

Volatility is a framework for extracting digital artifacts from volatile memory (RAM) samples.

- [Use volatility 2 & 3 with docker](https://github.com/Abyss-W4tcher/ab4yss-tools)

## Volatility 2

- [Volatility 2](https://github.com/volatilityfoundation/volatility) - Volatility2 framework
- [AutoVolatility](https://github.com/carlospolop/autoVolatility/tree/master) - Run several volatility plugins at the same time

## Profiles

- [Linux profiles (Debian, Ubuntu, Fedora, Almalinux, RockyLinux)](https://github.com/Abyss-W4tcher/volatility2-profiles)
- [MacOS & Linux profiles](https://github.com/volatilityfoundation/profiles)

### Plugins

- [BitLocker 1](https://github.com/breppo/Volatility-BitLocker) - Plugin that retrieves the Full Volume Encryption Key (FVEK) in memory
- [BitLocker 2](https://github.com/elceef/bitlocker) - Plugin finds and extracts Full Volume Encryption Key (FVEK) from memory dumps and/or hibernation files
- [BitLocker 3](https://github.com/tribalchicken/volatility-bitlocker) - Volatility plugin to extract BitLocker Full Volume Encryption Keys (FVEK)
- [Doppelfind - Process Doppelganging](https://github.com/kslgroup/Process-Doppelganging-Doppelfind) - plugin to detect Process Doppelganging
- [impfuzzy](https://github.com/JPCERTCC/impfuzzy/tree/master/impfuzzy_for_Volatility) - Plugin for comparing the impfuzzy and imphash. This plugin can be used to scan malware in memory image.
- [apt17scan](https://github.com/JPCERTCC/aa-tools/blob/master/apt17scan.py) - Plugin for Detecting APT17 malware
- [cobaltstrikescan](https://github.com/JPCERTCC/aa-tools/blob/master/cobaltstrikescan.py) - Plugin for Detecting Cobalt Strike Beacon
- [redleavesscan](https://github.com/JPCERTCC/aa-tools/blob/master/redleavesscan.py) - Plugin for Detecting RedLeaves Malware
- [MalConfScan](https://github.com/JPCERTCC/MalConfScan) - Plugin extracts configuration data of known malware
- [uninstallinfo](https://github.com/superponible/volatility-plugins/blob/master/uninstallinfo.py) - Dumps `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` from memory
- [Prefetch](https://github.com/superponible/volatility-plugins/blob/master/prefetch.py) - scan memory for prefetch files and dump filename and timestamps
- [idxparser](https://github.com/superponible/volatility-plugins/blob/master/idxparser.py) - scan memory Java IDX files and extract details
- [firefoxhistory](https://github.com/superponible/volatility-plugins/blob/master/firefoxhistory.py) - firefoxhistory, firefoxcookies, and firefoxdownloads plugins to extract the following firefox history data: moz_places, moz_cookies, and moz_downloads 
- [chromehistory](https://github.com/superponible/volatility-plugins/blob/master/chromehistory.py) - chromehistory, chromevisits, chromesearchterms, chromedownloads, chromedownloadchains, and chromecookies plugins to extract Chrome SQLite artifacts
- [sqlite_help](https://github.com/superponible/volatility-plugins/blob/master/sqlite_help.py) - supporting functions SQLite used in Firefox and Chrome plugins
- [trustrecords](https://github.com/superponible/volatility-plugins/blob/master/trustrecords.py) - extract Office TrustRecords registry key information
- [ssdeepscan](https://github.com/superponible/volatility-plugins/blob/master/ssdeepscan.py) - like yarascan, but searches for pages matching an ssdeep hash
- [malfinddeep](https://github.com/superponible/volatility-plugins/blob/master/malfinddeep.py) - whitelist code found by malfind based on an ssdeep hash
- [apihooksdeep](https://github.com/superponible/volatility-plugins/blob/master/apihooksdeep.py) - whitelist code found by apihooks based on an ssdeep hash
- [LastPass](https://github.com/kevthehermit/volatility_plugins/tree/main/vol2/lastpass) - Read browser memory space and attempt to recover any resident artefact's.
- [USBSTOR](https://github.com/kevthehermit/volatility_plugins/tree/main/vol2/usbstor) - Scans registries for values relating to USB devices plugged in to the system.
- [AutoRuns](https://github.com/tomchop/volatility-autoruns) - Finding persistence points (also called "Auto-Start Extensibility Points", or ASEPs) is a recurring task of any investigation potentially involving malware.
- [Volatility Explorer](https://github.com/memoryforensics1/VolExp) - This program functions similarly to Process Explorer/Hacker, but additionally it allows the user access to a Memory Dump
- [zbotscan](https://github.com/INTECOCERT/volatility_plugins) - Zeusbot plugin
- [zeusscan1](https://github.com/mgoffin/malwarecookbook/blob/master/zeusscan/zeusscan1.py) - Zeusbot 1 plugin
- [zeusscan2](https://github.com/mgoffin/malwarecookbook/blob/master/zeusscan/zeusscan2.py) - Zeusbot 2 plugin
- [browserhooks](https://github.com/eset/volatility-browserhooks) - Plugin to detect various types of hooks as performed by banking Trojans
- [OpenVPN credentials extractor](https://github.com/Phaeilo/vol-openvpn) - Plugin that can extract credentials from the memory of an OpenVPN process
- [HollowFind](https://github.com/monnappa22/HollowFind) - Plugin to detect different types of process hollowing techniques used in the wild to bypass, confuse, deflect and divert the forensic analysis techniques
- [FileVault2](https://github.com/tribalchicken/volatility-filevault2) - Plugin which attempts to extract Apple FileVault 2 Volume Master Keys.
- [dnscache](https://github.com/mnemonic-no/dnscache) - Plugin to extract the Windows DNS Resolver Cache.
- [dyrescan](https://github.com/kudelskisecurity/Volatility-plugins/blob/master/dyrescan.py) - Dyre is a banking malware discovered in middle of 2014
- [mimikatz](https://github.com/shr3ddersec/volatility-plugins/blob/master/mimikatz.py) - Mimikatz plugin
- [OpenSSH Session Key Recovery](https://github.com/fox-it/OpenSSH-Session-Key-Recovery) - Recover the OpenSSH session keys used to encrypt/ decrypt SSH traffic.
- [DLLInjectionDetection](https://github.com/Soterball/DLLInjectionDetection/tree/master) - DLLInjectionDetection
- [ACPI rootkit scan](https://github.com/mdenzel/ACPI-rootkit-scan) - Plugin to detect ACPI rootkits
- [ProcInjectionsFind](https://github.com/darshantank/ProcInjectionsFind/tree/main) - plugin runs against malware-infected memory images or memory of live VMs and examines each memory region of all running processes to conclude if it is the result of process injection.
- [Malfofind](https://github.com/volatilityfoundation/community/blob/master/DimaPshoul/malfofind.py) - Find indications of process hollowing/RunPE injections
- [Psinfo](https://github.com/monnappa22/Psinfo) - plugin which collects the process related information from the VAD (Virtual Address Descriptor) and PEB (Process Enivornment Block) and displays the collected information and suspicious memory regions for all the processes running on the system
- [malprocfind](https://github.com/volatilityfoundation/community/blob/master/CsabaBarta/malprocfind.py) - Finds malicious processes based on discrepancies from observed, normal behavior and properties
- [SchTasks](https://github.com/volatilityfoundation/community/blob/master/BartoszInglot/schtasks.py) - Scans for and parses potential Scheduled Task (.JOB) files
- [Other plugins 1](https://github.com/volatilityfoundation/community)

---

## Volatility 3

Volatility3 made a move away from profiles and instead uses **[Symbol Tables](https://volatility3.readthedocs.io/en/latest/basics.html#symbol-tables)**. For Linux these tables are generated by parsing a matching debug kernel extracting all the symbol structures and creating an Intermediate Symbol Format (ISF) file that can be processed by volatility3. These are NOT compatible with Volatility2 profiles

- [Volatility 3](https://github.com/volatilityfoundation/volatility3)
- [Windows Symbol Tables for Volatility 3](https://github.com/JPCERTCC/Windows-Symbol-Tables)
- [How to Use Volatility 3 Offline](https://blogs.jpcert.or.jp/en/2021/09/volatility3_offline.html)
- [Generate an ISF file for Volatitlity3](https://github.com/kevthehermit/volatility_symbols)
- [Volatility3 Linux ISF Server](https://isf-server.techanarchy.net/)

### Symbol

- [Windows Symbol Tables](https://github.com/JPCERTCC/Windows-Symbol-Tables) - Japan CERT
- [Linux symbols (Debian, Ubuntu, Almalinux, RockyLinux)](https://github.com/Abyss-W4tcher/volatility3-symbols)

### Plugins

- [Inodes](https://github.com/forensicxlab/volatility3_plugins/blob/main/inodes.py) - The plugin is a pushed verion of the lsof plugin extracting inode metadata information from each files.
- [Prefetch](https://github.com/forensicxlab/volatility3_plugins/blob/main/prefetch.py) - The plugin is scanning, extracting and parsing Windows Prefetch files from Windows XP to Windows 11.
- [impfuzzy](https://github.com/JPCERTCC/impfuzzy/tree/master/impfuzzy_for_Volatility3) - Plugin for comparing the impfuzzy and imphash. This plugin can be used to scan malware in memory image.
- [AnyDesk](https://github.com/forensicxlab/volatility3_plugins/blob/main/anydesk.py) - The plugin is scanning, extracting and parsing Windows AnyDesk trace files.
- [KeePass](https://github.com/forensicxlab/volatility3_plugins/blob/main/keepass.py) - The plugin is scanning the keepass process for potential password recovery following **CVE-2023-32784**
- [cobaltstrike](https://github.com/kevthehermit/volatility_plugins/blob/main/vol3/cobaltstrike/cobaltstrike.py) - Scans process memory for each process to identify CobaltStrike config and prints the config elements
- [Password Managers](https://github.com/kevthehermit/volatility_plugins/blob/main/vol3/passwordmanagers/passwordmanagers.py) - Extracts cached passwords from browser process memory. Supports: **Lastpass**
- [Rich Header](https://github.com/kevthehermit/volatility_plugins/blob/main/vol3/richheader/richheader.py) - Prints the XOR Key and Rich Header Hash for all process executables.
- [ZoneID3](https://github.com/kevthehermit/volatility_plugins/blob/main/vol3/zone-identifier/zoneid3.py) - Scans memory for ZoneIdentifier 3 ADS streams assocaited with files downloaded from the internet
- [pypykatz](https://github.com/skelsec/pypykatz-volatility3) - pypykatz plugin for volatility3 framework
- [apisearch](https://github.com/f-block/volatility-plugins/blob/main/apisearch.py) - This plugin helps identifying pointers to APIs (functions defined in loaded DLLs). It does that by iterating over all loaded DLLs, enumerating their exports and searching for any pointers to the exported functions. 
- [imgmalfind](https://github.com/f-block/volatility-plugins/blob/main/imgmalfind.py) - This plugin reveals modifications to mapped image files.
- [Autoruns](https://github.com/Telindus-CSIRT/volatility3-autoruns) - Finding persistence points (also called "Auto-Start Extensibility Points", or ASEPs) is a recurring task of any investigation potentially involving malware. (Port of tomchop's autoruns plugin for Volatility 3)
- [OpenSSH Session Key Recovery](https://github.com/fox-it/OpenSSH-Session-Key-Recovery) - Recover the OpenSSH session keys used to encrypt/ decrypt SSH traffic.
- [CryptoScan](https://github.com/BoB10th-BTC/CryptoScan/tree/master) - To find coin's address with regex
- [Stelte Syslog](https://github.com/volatilityfoundation/community3/tree/master/Stelte_Syslog) - Sending Volatility output to a syslog server
- [Stelte Evtx](https://github.com/volatilityfoundation/community3/tree/master/Stelte_Evtx) - Provides the capability to extract evtx entries from physical memory of Windows systems
- [Sheffer Shaked Docker](https://github.com/volatilityfoundation/community3/tree/master/Sheffer_Shaked_Docker) - forensics of Docker containers.
- [MountInfo](https://github.com/volatilityfoundation/community3/tree/master/Moreira_Mountinfo) - Previous Volatility file system analysis capabilities did not fully enumerate information related to containers, which left much work on part of the analyst. This plugin closes that gap by replicating the per-process mount information as exported in the /proc/<pid>/mountinfo file on live systems.
- [rootkit](https://github.com/AsafEitani/rootkit_plugins/) - plugins that detect advanced rootkit hooking methods.
- [Hyper-V](https://github.com/gerhart01/Hyper-V-Tools/tree/main/Plugin_for_volatility) - Hyper-V memory plugin for volatility
- [CheckSpoof](https://github.com/orchechik/check_spoof) - A useful and old technique analysts use for detecting anomalous activity is identifying parent-child relationships. Today attackers can change the Parent PID (PPID) quite
- [Others plugin 1](https://github.com/f-block/volatility-plugins)
- [Others plugin 2](https://github.com/volatilityfoundation/community3)

### GUI

- [Volatility Explorer](https://github.com/memoryforensics1/Vol3xp) - This program functions similarly to Process Explorer/Hacker, but additionally it allows the user access to a Memory Dump
- [Orochi](https://github.com/LDO-CERT/orochi) - The Volatility Collaborative GUI
- [VolWeb](https://github.com/k1nd0ne/VolWeb) - A centralized and enhanced memory analysis platform

## Challenges

- [2022 Volatility Plugin Contest](https://volatility-labs.blogspot.com/2022/07/the-10th-annual-volatility-plugin-contest.html)
- [2021 Volatility Plugin Contest](https://volatility-labs.blogspot.com/2022/02/the-2021-volatility-plugin-contest-results.html)
- [2020 Volatility Plugin Contest](https://volatility-labs.blogspot.com/2020/11/the-2020-volatility-plugin-contest-results.html)
- [2019 Volatility Plugin & Analysis Contests](https://volatility-labs.blogspot.com/2019/11/results-from-2019-volatility-contests.html)
- [2018 Volatility Plugin & Analysis Contests](https://volatility-labs.blogspot.com/2018/11/results-from-annual-2018-volatility-contests.html)
- [2017 Volatility Plugin Contest](https://volatility-labs.blogspot.com/2017/11/results-from-5th-annual-2017-volatility.html)
- [2016 Volatility Plugin Contest](https://volatility-labs.blogspot.com/2016/12/results-from-2016-volatility-plugin.html)
- [2015 Volatility Plugin Contest](https://www.volatilityfoundation.org/2015)
- [2014 Volatility Plugin Contest](https://www.volatilityfoundation.org/2014-cjpn)
- [2013 Volatility Plugin Contest](https://www.volatilityfoundation.org/2013-c19yz)

## Ressources

- https://github.com/digitalisx/awesome-memory-forensics/blob/main/README.md

## Active repo

- https://github.com/kevthehermit/volatility_plugins (waiting for 2 new volatility3 plugins)