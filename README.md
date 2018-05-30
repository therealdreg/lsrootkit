# lsrootkit
Rootkit Detector for UNIX (the actual beta only works as expected in Linux)

Tool created in 2013 to complement Unhide Forensic Tool: http://www.unhide-forensics.info/

**Warning!!: the code is bullshit (is only a beta prototype).**

# Compile & Run
Compile: gcc -lpthread -o lsrootkit lsrootkit.c

If fails try: gcc -pthread -o lsrootkit lsrootkit.c

Execute: ./lsrootkit

**Very Important: if lsrootkit process crash you can have a rootkit in the system with some bugs: memory leaks etc.**

Real scenario example: vlany rootkit crash the process because their readdir hook: https://github.com/mempodippy/vlany

![vlanycrash](https://github.com/David-Reguera-Garcia-Dreg/lsrootkit/blob/master/vlanybrute.png)

This is very funny because vlany is designed to avoid this kind of tool. It tries avoid GID bruteforcing using xattrs in files instead of a MAGIC_GID. But the code in their readdir hook crash the process in 2-3 mins. This kind of crash can be interpreted like: there are something bad coded hooking me. 

Also vlany tries avoid GID bruteforcing in processes but lsrootkit can detect their setgid safeguard.

# Features

Processes: Full GIDs process occupation (processes GID bruteforcing)

Files: Full GIDs file occupation (files GID bruteforcing)

The idea is very simple: a lot of rootkits uses a MAGIC GID (a random GID generated) to hide processes and files. This tool find rootkits bruteforcing all GIDs possible in the system. 

It also can detect some rootkits safe-guards and strange things in the hooked code. 

lsrootkit needs run as root or with caps for bruteforce: setgid & chown.

**Warning: each analysis-feature can take: 48 hours in a QUADCORE CPU 3100.000 MHz (NO SSD).**

## For processes

1) It creates a PARENT and a CHILD processes.
2) The CHILD in a loop from 0 to MAX_GID_POSSIBLE calls to: setgid(ACTUAL_GID).
3) The CHILD send the new GID to PARENT via pipe. (It calls to getgid() to get the new gid).
4) If the GID returned from getgid() is different from ACTUAL_GID (used in setgid(ACTUAL_GID)): Alert! this is impossible, can be a rootkit doing strange things. 
5) If setgid(ACTUAL_GID) fails: Alert! this is impossible, can be a rootkit doing strange things.
6) If in two loop-iterations the GID returned is the same (last_gid == new_gid): Alert! this is impossible, can be a rootkit doing strange things. 
7) In each iteration, the PARENT check if exist the PID of the child in: /proc (readdir/getdents). When the child PID is not listed: bingo!! the new GID is the MAGIC_GID of a rootkit. The rootkit is hidding the process.
8) Also the PARENT check if the ACTUAL_GID recived from the PIPE is the same listed in /proc/pid/status. When is different: Alert! this is impossible, can be a rootkit doing strange things.

*IMPORTANT: The 4, 5 and 6 checks are useful in real scenarios. Example: when the ACTUAL_GID of a process is the MAGIC_GID some rootkits make impossible for the process to change their GID, this is a safe guard to avoid detections. Then, we are detecting the safe guard of the rootkit.

How the check if the analysis is working good:

```
[!! root@fr33project 14:17:21 ~]# ps o user,pid,gid,comm | grep lsrootkit
root      2614     0 lsrootkit
root      2631 828390172 lsrootkit
root      2632 1096822881 lsrootkit
root      2633 1365307256 lsrootkit
root      2634 1633704931 lsrootkit
root      2635 1902096925 lsrootkit
root      2636 -2124457736 lsrootkit
root      2637 559915649 lsrootkit
root      2638 -1855971818 lsrootkit
root      2639 -1319109121 lsrootkit
root      2640 -1587593627 lsrootkit
root      2641 -1050718186 lsrootkit
root      2642 -782346219 lsrootkit
root      2643 -513848494 lsrootkit
root      2644 -245456886 lsrootkit
root      2645 291438594 lsrootkit
root      2646 23009595 lsrootkit
```

```
[!! root@fr33project 14:17:27 ~]# ps o user,pid,gid,comm | grep lsrootkit
root      2614     0 lsrootkit
root      2631 828395894 lsrootkit
root      2632 1096828582 lsrootkit
root      2633 1365313071 lsrootkit
root      2634 1633710689 lsrootkit
root      2635 1902102633 lsrootkit
root      2636 -2124452025 lsrootkit
root      2637 559921448 lsrootkit
root      2638 -1855966060 lsrootkit
root      2639 -1319103376 lsrootkit
root      2640 -1587587943 lsrootkit
root      2641 -1050712491 lsrootkit
root      2642 -782340414 lsrootkit
root      2643 -513842741 lsrootkit
root      2644 -245451101 lsrootkit
root      2645 291444348 lsrootkit
root      2646 23015307 lsrootkit
```

You should see 16 processes changing their GID very fast in each ps.

## For files

1) It creates a loop from 0 to MAX_GID_POSSIBLE calling to: chown(ACTUAL_GID).
2) If the GID returned from stat() is different from ACTUAL_GID (used in chown(ACTUAL_GID)): Alert! this is impossible, can be a rootkit doing strange things. 
3) If chown(ACTUAL_GID) or stat() fails: Alert! this is impossible, can be a rootkit doing strange things.
4) If in two loop-iterations the GID returned is the same (last_gid == new_gid): Alert! this is impossible, can be a rootkit doing strange things. 
5) In each iteration, the process checks if exist the file in the directory (readdir/getdents). When the file is not listed: bingo!! the new GID is the MAGIC_GID of a rootkit. The rootkit is hidding the file.


How the check if the analysis is working good: ls in the temp path of lsrootkit 

```
[!! root@fr33project 14:22:04 ~]# ls -l /tmp/lsroot.SdbfpS
total 0
-rw-r--r-- 1 root 4026594762 0 May 27 14:21 140675378259712.files
-rw-r--r-- 1 root 3758158753 0 May 27 14:21 140675388749568.files
-rw-r--r-- 1 root 3489726270 0 May 27 14:21 140675399239424.files
-rw-r--r-- 1 root 3221289355 0 May 27 14:21 140675409729280.files
-rw-r--r-- 1 root 2952853954 0 May 27 14:21 140675420219136.files
-rw-r--r-- 1 root 2684416720 0 May 27 14:21 140675430708992.files
-rw-r--r-- 1 root 2415982578 0 May 27 14:21 140675441198848.files
-rw-r--r-- 1 root 2147546885 0 May 27 14:21 140675451688704.files
-rw-r--r-- 1 root 1879112486 0 May 27 14:21 140675462178560.files
-rw-r--r-- 1 root 1610675753 0 May 27 14:21 140675472668416.files
-rw-r--r-- 1 root 1342242039 0 May 27 14:21 140675483158272.files
-rw-r--r-- 1 root 1073805230 0 May 27 14:21 140675493648128.files
-rw-r--r-- 1 root  805369459 0 May 27 14:21 140675504137984.files
-rw-r--r-- 1 root  536932663 0 May 27 14:21 140675514627840.files
-rw-r--r-- 1 root  268497886 0 May 27 14:21 140675525117696.files
-rw-r--r-- 1 root      60838 0 May 27 14:21 140675535607552.files
```

```
[!! root@fr33project 14:22:10 ~]# ls -l /tmp/lsroot.SdbfpS
total 0
-rw-r--r-- 1 root 4026614564 0 May 27 14:21 140675378259712.files
-rw-r--r-- 1 root 3758177213 0 May 27 14:21 140675388749568.files
-rw-r--r-- 1 root 3489745995 0 May 27 14:21 140675399239424.files
-rw-r--r-- 1 root 3221308027 0 May 27 14:21 140675409729280.files
-rw-r--r-- 1 root 2952872962 0 May 27 14:21 140675420219136.files
-rw-r--r-- 1 root 2684435702 0 May 27 14:21 140675430708992.files
-rw-r--r-- 1 root 2416001384 0 May 27 14:21 140675441198848.files
-rw-r--r-- 1 root 2147565897 0 May 27 14:21 140675451688704.files
-rw-r--r-- 1 root 1879132036 0 May 27 14:21 140675462178560.files
-rw-r--r-- 1 root 1610694197 0 May 27 14:21 140675472668416.files
-rw-r--r-- 1 root 1342261085 0 May 27 14:21 140675483158272.files
-rw-r--r-- 1 root 1073823702 0 May 27 14:21 140675493648128.files
-rw-r--r-- 1 root  805388313 0 May 27 14:21 140675504137984.files
-rw-r--r-- 1 root  536951073 0 May 27 14:21 140675514627840.files
-rw-r--r-- 1 root  268516353 0 May 27 14:21 140675525117696.files
-rw-r--r-- 1 root      80117 0 May 27 14:21 140675535607552.files
```

You should see 16 files changing their GID very fast in each ls -l

## Help & cmdline


```
 lsrootkit beta0.1 - Rootkit Detector for UNIX
-
MIT LICENSE - Copyright(c) 2013
by David Reguera Garcia aka Dreg - dreg@fr33project.org
https://github.com/David-Reguera-Garcia-Dreg
http://www.fr33project.org
- 

For program help type: ./main --help

         
lsrootkit options (all analysis are ON by default):

      --disable-each-display Disable each display messages
      --only-gid-files       Only bruteforce files GID
      --only-gid-processes   Only bruteforce processes GID
      --report-path[=FILE]   Set new report path. it needs also the name.
                             Example: --report-path=/root/analysis.txt
      --tmp-path[=FILE]      Set new temp path dir. Example:
                             --tmp-path=/var/tmp
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```

# Detected Rootkits

Please, I need your help to mantain this list!! (create an issue with info)

- enyelkm: LKM rootkit for Linux x86 with the 2.6 kernel. https://github.com/David-Reguera-Garcia-Dreg/enyelkm
  - detected via: normal detection.
- vlany: Linux LD_PRELOAD rootkit (x86 and x86_64 architectures). https://github.com/mempodippy/vlany
  - detected via: crash of the process & setgid safe-guard.
- reptile: LKM Linux rootkit. https://github.com/f0rb1dd3n/Reptile
  - detected via: normal detection.
- jynx2: LD_PRELOAD userland rootkit based on the original JynxKi. https://github.com/chokepoint/Jynx2
  - detected via: normal detection.
- jynxkit: LD_PRELOAD userland rootkit for Linux. https://github.com/chokepoint/jynxkit
  - detected via: normal detection.

# Referenced by

empty
