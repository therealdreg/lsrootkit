# lsrootkit
Rootkit Detector for UNIX (the actual beta only works as expected in Linux)

Tool created in 2013 to complement Unhide Forensic Tool: http://www.unhide-forensics.info/

**Warning!!: the code is bullshit (is only a beta prototype).**

# Compile & Run
Compile: gcc -lpthread -o lsrootkit lsrootkit.c

If fails try: gcc -pthread -o lsrootkit lsrootkit.c

Execute: ./lsrootkit

**Very Important: if lsrootkit process crash you can have a rootkit in the system with some bugs: memory leaks etc.**

Real scenario example: vlany rootkit crash the process because their readdir hook

![vlanycrash](https://github.com/David-Reguera-Garcia-Dreg/lsrootkit/blob/master/vlanybrute.png)

Is very funny because vlany is designed to avoid this kind of tool. It tries avoid GID bruteforcing using xattrs in files instead of a MAGIC_GID. But the code in their readdir hook crash the process in 2-3 mins. This kind of crash can be interpreted like: there are something bad coded hooking me. Also vlany tries avoid GID bruteforcing in processes but lsrootkit can detects their setgid safeguard.

# Features

Processes: Full GIDs process occupation (processes GID bruteforcing)

Files: Full GIDs file occupation (files GID bruteforcing)

The idea is very simple: a lot of rootkits uses a MAGIC GID (a random GID generated) to hide processes and files. This tool find rootkits bruteforcing all GIDs possible in the system. 

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

## For files

1) It creates a loop from 0 to MAX_GID_POSSIBLE calling to: chown(ACTUAL_GID).
2) If the GID returned from stat() is different from ACTUAL_GID (used in chown(ACTUAL_GID)): Alert! this is impossible, can be a rootkit doing strange things. 
3) If chown(ACTUAL_GID) or stat() fails: Alert! this is impossible, can be a rootkit doing strange things.
4) If in two loop-iterations the GID returned is the same (last_gid == new_gid): Alert! this is impossible, can be a rootkit doing strange things. 
5) In each iteration, the process checks if exist the file in the directory (readdir/getdents). When the file is not listed: bingo!! the new GID is the MAGIC_GID of a rootkit. The rootkit is hidding the file.

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
- vlany: Linux LD_PRELOAD rootkit (x86 and x86_64 architectures). https://github.com/mempodippy/vlany
- reptile: LKM Linux rootkit. https://github.com/f0rb1dd3n/Reptile
- jynx2: LD_PRELOAD userland rootkit based on the original JynxKi. https://github.com/chokepoint/Jynx2

# Referenced by

-
