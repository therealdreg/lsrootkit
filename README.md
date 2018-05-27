# lsrootkit
Rootkit Detector for UNIX (the actual beta only works as expected in Linux)

Tool created in 2013 to complement Unhide Forensic Tool: http://www.unhide-forensics.info/

**Warning!!: the code is bullshit (is only a beta prototype).**

# Compile & Run
Compile: gcc -lpthread -o lsrootkit lsrootkit.c

If fails try: gcc -pthread -o lsrootkit lsrootkit.c

Execute: ./lsrootkit

**Very Important: if lsrootkit process crash you can have a rootkit in the system with some bugs: memory leaks etc.**

# Features

Processes: Full GIDs process occupation (processes GID bruteforcing)

Files: Full GIDs file occupation (files GID bruteforcing)

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
