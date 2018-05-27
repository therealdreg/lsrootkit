# lsrootkit
Rootkit Detector for UNIX. Tool created in 2013 to complement Unhide Forensic Tool: http://www.unhide-forensics.info/

Warning!!: the code is bullshit (is only a beta prototype).

# Compile & Run
Compile: gcc -lpthread -o lsrootkit lsrootkit.c

If fails try: gcc -pthread -o lsrootkit lsrootkit.c

Execute: ./lsrootkit

Very Important: if lsrootkit process crash you can have a rootkit in the system with some bugs: memory leaks etc.
