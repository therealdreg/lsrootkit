/* Warning!!: the code is bullshit (is only a beta prototype).
-
Compile: gcc -lpthread -o lsrootkit lsrootkit.c
If fails try: gcc -pthread -o lsrootkit lsrootkit.c
Execute: ./lsrootkit
Very Important: if lsrootkit process crash you can have a rootkit in the system with some bugs: memory leaks etc.
-
MIT LICENSE - Copyright (c) lsrootkit - 2013
by: David Reguera Garcia aka Dreg - dreg@fr33project.org
https://github.com/David-Reguera-Garcia-Dreg
http://www.fr33project.org

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#define _POSIX_C_SOURCE 200809L

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>

#include <argp.h>

#include <sys/time.h>

#include <signal.h>

#define PROC_GID_BYTES 1000
#define LSROOT_TMP_TEMPLATE "/lsroot.XXXXXX"
#define NUM_THREADS 16 /* MUST BE POWER OF 2 */
#define EACH_DISPLAY 60000
#define MAX_VALUE(a) (((unsigned long long)1 << (sizeof(a) * CHAR_BIT)) - 1)
#define MYARRAYSIZE(a) (sizeof(a) / sizeof(*(a)))
#define SPEED_TEST "48 hours in a QUADCORE CPU 3100.000 MHz (NO SSD)"


#define _PCRED   "\x1B[31m"
#define _PCGRN   "\x1B[32m"
#define _PCYEL   "\x1B[33m"
#define _PCBLU   "\x1B[34m"
#define _PCMAG   "\x1B[35m"
#define _PCCYN   "\x1B[36m"
#define _PCWHT   "\x1B[37m"
#define _PCRESET "\x1B[0m"

int disable_colors = 0;

#define DPRINT_MSG(oustream, colour, tag, ...) if (disable_colors == 0) { fprintf(oustream, colour tag _PCRESET __VA_ARGS__ ); } else { fprintf(oustream, tag __VA_ARGS__ ); }
#define DERROR_MSG(...)  DPRINT_MSG(stdout, _PCRED,  " [ERROR!!] ", __VA_ARGS__) //  fprintf(stderr, _PCRED " [ERROR!!] " _PCRESET __VA_ARGS__ );
#define DWARNING_MSG(...) DPRINT_MSG(stdout, _PCYEL,  " [Warning] ", __VA_ARGS__) // fprintf(stdout, _PCYEL " [Warning] " _PCRESET __VA_ARGS__ );
#define DOK_MSG(...) DPRINT_MSG(stdout, _PCGRN,  " [ok] ", __VA_ARGS__) // fprintf(stdout, _PCGRN " [ok] " _PCRESET __VA_ARGS__ );
#define DINFO_MSG(...) DPRINT_MSG(stdout, _PCCYN,  " [info] ", __VA_ARGS__) // fprintf(stdout, _PCCYN " [info] " _PCRESET __VA_ARGS__ );
#define DDETECTED_MSG(...) DPRINT_MSG(stdout, _PCRED,  " [rootkit_detected!!] ", __VA_ARGS__) // fprintf(stdout, _PCRED " [rootkit_detected!!] " _PCRESET __VA_ARGS__ );
#define DNODETECTED_MSG(...) DPRINT_MSG(stdout, _PCBLU,  " [NO_rootkits_detected] ", __VA_ARGS__) // fprintf(stdout, _PCBLU " [NO_rootkits_detected] " _PCRESET __VA_ARGS__ );
#define DRAW_MSG(...) fprintf(stdout, __VA_ARGS__ );

struct arguments
{
    char* tmp_path;
    char* report_path;
    int disable_each_display;
    int only_processes_gid;
    int only_files_gid;
    int only_processes_kill;
    int disable_colors;
};

typedef struct THS_DAT_s
{
    char* tmp_dir;
    FILE* report_path;
    pthread_mutex_t* mutex;
    unsigned int first_gid;
    unsigned int last_gid;
    int detected;
    struct arguments* arguments;
} THD_DAT_t;


char* CreateTempDir(void);
void* BruteForceGIDProcesses(void* arg);
void* BruteForceGIDFiles(void* arg);
int main(int argc, char* argv[]);
int CheckProcAccess(void);

typedef void* (*THREAD_FUNC_t)(void* arg);

int CheckRights(char* tmp_path)
{
    char test_file[PATH_MAX];
    FILE* file = NULL;
    int retf = -1;
    struct stat statbuf;
    gid_t actual_gid = 8;

    DINFO_MSG("Checking this-process rights\n");

    if (CheckProcAccess() == -1)
    {
        return -1;
    }

    memset(test_file, 0, sizeof(test_file));
    memset(&statbuf, 0, sizeof(statbuf));

    sprintf(test_file, "%s/_test", tmp_path);

    DINFO_MSG("Checking rights with file: %s\n", test_file);

    retf = -1;
    file = fopen(test_file, "wb+");
    if (file == NULL)
    {
        perror(test_file);
    }
    else
    {
        if (chown(test_file, 0, 0) == 0)
        {
            statbuf.st_gid = 8;
            if (stat(test_file, &statbuf) == 0)
            {
                if (statbuf.st_gid == 0)
                {
                    if (chown(test_file, 1, 1) == 0)
                    {
                        statbuf.st_gid = 8;
                        if (stat(test_file, &statbuf) == 0)
                        {
                            if (statbuf.st_gid == 1)
                            {
                                actual_gid = getgid();
                                if (setgid(0) == 0)
                                {
                                    if (getgid() == 0)
                                    {
                                        if (setgid(1) == 0)
                                        {
                                            if (getgid() == 1)
                                            {
                                                DOK_MSG("Rights ok!!\n");
                                                retf = 0;
                                            }
                                        }
                                    }
                                }
                                setgid(actual_gid);
                            }
                        }
                    }
                }
            }
        }

        fclose(file);
        unlink(test_file);
    }

    if (retf != 0)
    {
        DERROR_MSG("Rights fail!!\n");
    }

    return retf;
}


static inline int ExistStartNumericInDir(char* path, char* pid_string, int* exist)
{
    DIR* dir;
    struct dirent* ent;
    register char c;

    *exist = 0;

    if ((dir = opendir(path)) != NULL)
    {
        while ((ent = readdir(dir)) != NULL)
        {
            c = ent->d_name[0];

            if (c >= '0' && c <= '9' && strcmp(ent->d_name, pid_string) == 0)
            {
                *exist = 1;
                break;
            }
        }
        closedir(dir);
    }
    else
    {
        return -1;
    }

    return 0;
}


// NOTE: /proc/[pid] group is real gid unless process' dumpable attribute is other than 1
static inline int GetGIDFromStatProcPID(unsigned int* gid, char* procfs_pid_dir_name)
{
    int stat_ret = 0;
    struct stat statbuf;

    stat_ret = stat(procfs_pid_dir_name, &statbuf);
    if (stat_ret == -1) {
        *gid = 0;
        return -1;
    }

    *gid = statbuf.st_gid;

    return 0;
}

static inline int GetGIDFromPID(unsigned int* gid, char* procfs_status_file_name)
{
    char buf[PROC_GID_BYTES];
    char* aux;
    int procfs_pid;
    int retf = -1;
    ssize_t read_ret = 0;

    *gid = 0;

    procfs_pid = open(procfs_status_file_name, O_RDONLY);
    if (procfs_pid == -1)
    {
        return -1;
    }
    read_ret = read(procfs_pid, buf, sizeof(buf) - 1);
    if ((read_ret != -1) && (read_ret != 0))
    {
        buf[sizeof(buf) - 1] = '\0';
        aux = buf;
        do
        {
            aux = strchr(aux + 1, '\n');
            if (aux != NULL)
            {
                aux++;
                if (aux[0] == 'G')
                {
                    if (sscanf(aux, "Gid:\t%u\t", gid) == 1)
                    {
                        retf = 0;
                        break;
                    }
                }
            }
        } while ((aux != NULL) && (aux[0] != '\0'));
    }

    close(procfs_pid);

    return retf;
}

int CheckProcAccess(void)
{
    char pid_string[PATH_MAX];
    char procpath[PATH_MAX];
    unsigned int gid = 0;
    pid_t child_pid = 0;
    int retf = -1;
    int exist = 0;

    DINFO_MSG("Checking /proc access & info returned\n");

    memset(pid_string, 0, sizeof(pid_string));
    memset(procpath, 0, sizeof(procpath));

    retf = -1;
    child_pid = fork();
    if (child_pid == 0)
    {
        while (1)
        {
            sleep(1);
        }
    }
    else
    {
        DOK_MSG("created child pid: %d\n", child_pid)

        sprintf(pid_string, "%d", (int)child_pid);
        exist = 0;
        if (ExistStartNumericInDir((char*) "/proc", pid_string, &exist) == -1)
        {
            DERROR_MSG("dont access to /proc\n");
        }
        else
        {
            DOK_MSG("accessing to /proc\n");
            if (exist == 0)
            {
                DERROR_MSG("pid dont exist in /proc\n");
            }
            else
            {
                DOK_MSG("pid exist in /proc\n");

                sprintf(procpath, "/proc/%s/status", pid_string);
                if (GetGIDFromPID(&gid, procpath) == -1)
                {
                    DERROR_MSG("%s DONT exist\n", procpath);
                }
                else
                {
                    DOK_MSG("%s exist, parent child: %u, child gid: %u\n", procpath, (unsigned int) getgid(), gid);
                    if (gid != getgid())
                    {
                        DERROR_MSG("gid of child and parent is different\n");
                    }
                    else
                    {
                        DOK_MSG("gid of child and parent is the same\n");
                        retf = 0;
                    }
                }
            }
        }

        if (kill(child_pid, SIGKILL) == 0)
        {
            DOK_MSG("killed child: %d\n", child_pid);
        }
        else
        {
            DERROR_MSG("killing child: %d\n", child_pid)
        }
    }

    return retf;
}

static inline char* CheckRootkitFilesGID(int chown_ret, int stat_ret, int exist_file_ret, int exist_in_tmp, unsigned int gid_detected, unsigned int actual_gid, unsigned int last_gid)
{
    char* rootkit_msg_detection = NULL;
    char* type = NULL;

    if (exist_file_ret == -1)
    {
        type = (char*) "tmp dir innaccesible";
    }
    else if (exist_in_tmp == 0)
    {
        type = (char*) "gid hidden from readdir tmp";
    }
    else if (chown_ret == -1)
    {
        type = (char*) "chown hooked";
    }
    else if (stat_ret == -1)
    {
        type = (char*) "stat hooked";
    }
    else if (gid_detected != actual_gid)
    {
        type = (char*) "gid_detected != actual_gid";
    }
    else if (gid_detected == last_gid)
    {
        type = (char*) "gid_detected == last_gid";
    }
    else if (gid_detected == 0)
    {
        type = (char*) "gid_detected == 0";
    }
    else
    {
        return NULL;
    }

    if (type == NULL)
    {
        return NULL;
    }

    /* I am too lazy to include a portable POSIX asprintf x) */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    if (asprintf(&rootkit_msg_detection, "type: %s - extra info: chown_ret: %d, stat_ret: %d, exist_file_ret: %d, exist_in_tmp: %d, gid_detected: %u, actual_gid: %u, last_gid: %u\n",
                 type, chown_ret, stat_ret, exist_file_ret, exist_in_tmp, gid_detected, actual_gid, last_gid) == -1)
    {
        return NULL;
    }
#pragma GCC diagnostic pop

    return rootkit_msg_detection;
}

static inline void ShowEachDisplay(unsigned int* cnt, unsigned int* remain, struct timeval* tv1, char* tag, unsigned int actual_gid, unsigned int last_gid)
{
    if ((*cnt % EACH_DISPLAY) == 0)
    {
        double estimated = 0;
        struct timeval tv2;
        unsigned int last_remain;

        last_remain = *remain;

        *remain = last_gid - actual_gid;

        gettimeofday(&tv2, NULL);
        if ((last_remain > 0) && ((last_remain - *remain) > 0))
        {
            estimated = (double)(tv2.tv_usec - tv1->tv_usec) / 1000000 + (double)(tv2.tv_sec - tv1->tv_sec);
            estimated = (double)(((((double)last_remain / (double)(last_remain - *remain)) * estimated) / 60) / 60);
        }
        gettimeofday(tv1, NULL);

        DINFO_MSG("t[%llu] - %s %s%u%s/%s%u%s remain: %s%u%s - aprox remain hours: %.2f %s\n",
                  (unsigned long long) pthread_self(),
                  tag,
                  disable_colors == 0 ? _PCCYN : "",
                  actual_gid,
                  disable_colors == 0 ? _PCRESET : "",
                  disable_colors == 0 ? _PCRED : "",
                  last_gid,
                  disable_colors == 0 ? _PCRESET : "",
                  disable_colors == 0 ? _PCGRN : "",
                  *remain,
                  disable_colors == 0 ? _PCRESET : "",
                  estimated,
                  estimated == 0 ? "calculating... be patient" : " ");
    }

    *cnt += 1;
}

static inline void RootkitDetected(char* tag, char* rootkit_msg_detection, THD_DAT_t* th_dat)
{
    DDETECTED_MSG("t[%llu] - %s rootkit detected!! %s\n\n", (unsigned long long) pthread_self(), tag, rootkit_msg_detection);

    pthread_mutex_lock(th_dat->mutex);
    fprintf(th_dat->report_path, "\n%s\n", rootkit_msg_detection);
    fflush(th_dat->report_path);
    pthread_mutex_unlock(th_dat->mutex);
    th_dat->detected = 1;
}


void* BruteForceGIDFiles(void* arg)
{
    THD_DAT_t* th_dat = (THD_DAT_t*)arg;
    char file_name[PATH_MAX];
    char full_path[PATH_MAX];
    unsigned int gid_detected = 0;
    unsigned int actual_gid = 0;
    unsigned int last_gid = 0;
    uid_t my_uid;
    struct stat statbuf;
    unsigned int i = EACH_DISPLAY;
    char* rootkit_msg_detection = NULL;
    int chown_ret = 0;
    int stat_ret = 0;
    int exist_file_ret;
    int exist_in_tmp;
    char file_name_ext[PATH_MAX];
    struct timeval tv1;
    unsigned int remain = 0;

    my_uid = getuid();

    memset(file_name, 0, sizeof(file_name));
    memset(full_path, 0, sizeof(full_path));
    memset(file_name_ext, 0, sizeof(file_name_ext));

    sprintf(file_name, "%llu", (unsigned long long) pthread_self());

    sprintf(file_name_ext, "%s.files", file_name);

    sprintf(full_path, "%s/%s", th_dat->tmp_dir, file_name_ext);

    DOK_MSG("t[%llu] - BruteForceGIDFiles New thread! GID range: %u - %u\n\t%s\n", (unsigned long long) pthread_self(), th_dat->first_gid, th_dat->last_gid, full_path);

    fclose(fopen(full_path, "wb+"));

    gettimeofday(&tv1, NULL);
    actual_gid = th_dat->first_gid;
    do
    {
        chown_ret = chown(full_path, my_uid, actual_gid);
        gid_detected = 0;
        statbuf.st_gid = 0;
        stat_ret = stat(full_path, &statbuf);
        if (stat_ret != -1)
        {
            last_gid = gid_detected;
            gid_detected = statbuf.st_gid;
        }
        exist_in_tmp = 0;
        exist_file_ret = ExistStartNumericInDir(th_dat->tmp_dir, file_name_ext, &exist_in_tmp);

        rootkit_msg_detection = CheckRootkitFilesGID(chown_ret, stat_ret, exist_file_ret, exist_in_tmp, gid_detected, actual_gid, last_gid);
        if (rootkit_msg_detection != NULL)
        {
            RootkitDetected((char*)"BruteForceGIDFiles", rootkit_msg_detection, th_dat);
            free(rootkit_msg_detection);
            rootkit_msg_detection = NULL;

            break;
        }

        if (th_dat->arguments->disable_each_display == 0)
        {
            ShowEachDisplay(&i, &remain, &tv1, (char*) "BruteForceGIDFiles", actual_gid, th_dat->last_gid);
        }
    } while (actual_gid++ != th_dat->last_gid);

    unlink(full_path);

    return NULL;
}

static inline char* CheckRootkitProcessesGID(int exist_in_proc_ret,
        int exist_in_proc,
        int proc_ret,
        unsigned int gid_from_proc,
        int statproc_ret,
        unsigned int gid_from_statproc,
        unsigned int gid_detected,
        unsigned int actual_gid,
        unsigned int last_gid)
{
    char* rootkit_msg_detection = NULL;
    char* type = NULL;

    if (exist_in_proc_ret == -1)
    {
        type = (char*) "/proc dir innaccesible";
    }
    else if (exist_in_proc == 0)
    {
        type = (char*) "gid hidden from readdir proc";
    }
    else if (proc_ret == -1)
    {
        type = (char*) "gid hidden from open proc/pid/status";
    }
    else if (gid_from_proc != gid_detected)
    {
        type = (char*) "gid_from_proc != gid_detected";
    }
    else if (statproc_ret == -1)
    {
        type = (char*) "gid hidden from open proc/pid";
    }
    else if (gid_from_statproc != gid_detected)
    {
        type = (char*) "gid_from_statproc != gid_detected";
    }
    else if (gid_detected != actual_gid)
    {
        type = (char*) "gid_detected != actual_gid";
    }
    else if (gid_detected == last_gid)
    {
        type = (char*) "gid_detected == last_gid";
    }
    else if (gid_detected == 0)
    {
        type = (char*) "gid_detected == 0";
    }
    else
    {
        return NULL;
    }

    if (type == NULL)
    {
        return NULL;
    }

    /* I am too lazy to include a portable POSIX asprintf x) */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    if (asprintf(&rootkit_msg_detection, "type: %s - extra info: exist_in_proc_ret: %d, exist_in_proc: %d, proc_ret: %d, gid_from_proc: %u, statproc_ret: %d, gid_from_statproc: %u, gid_detected: %u, actual_gid: %u, last_gid: %u",
                 type, exist_in_proc_ret, exist_in_proc, proc_ret, gid_from_proc, statproc_ret, gid_from_statproc, gid_detected, actual_gid, last_gid) == -1)
    {
        return NULL;
    }
#pragma GCC diagnostic pop

    return rootkit_msg_detection;
}

void _Parent(pid_t child_pid, int fd_child, int fd_parent, THD_DAT_t* th_dat)
{
    ssize_t write_ret = 0;
    ssize_t read_ret = 0;
    int proc_ret = 0;
    int statproc_ret = 0;
    unsigned int gid_detected = 0;
    unsigned int last_gid = 0;
    unsigned int actual_gid = 0;
    int read_state = 0;
    char procfs_status_file_name[PATH_MAX];
    char procfs_childpid_dir_name[PATH_MAX];
    unsigned int gid_from_proc = 0;
    unsigned int gid_from_statproc = 0;
    char* rootkit_msg_detection;
    unsigned int i = 0;
    char pid_string[PATH_MAX];
    int exist_in_proc;
    int exist_in_proc_ret;
    unsigned int remain = 0;
    struct timeval tv1;

    memset(procfs_status_file_name, 0, sizeof(procfs_status_file_name));
    sprintf(procfs_status_file_name, "/proc/%d/status", child_pid);

    memset(procfs_childpid_dir_name, 0, sizeof(procfs_childpid_dir_name));
    sprintf(procfs_childpid_dir_name, "/proc/%d", child_pid);

    memset(pid_string, 0, sizeof(pid_string));
    sprintf(pid_string, "%d", child_pid);

    read_state = 1;
    gettimeofday(&tv1, NULL);
    actual_gid = th_dat->first_gid;
    do
    {
        last_gid = gid_detected;
        read_ret = read(fd_child, &gid_detected, sizeof(gid_detected));
        gid_from_proc = 0;
        proc_ret = GetGIDFromPID(&gid_from_proc, procfs_status_file_name);
        gid_from_statproc = 0;
        statproc_ret = GetGIDFromStatProcPID(&gid_from_statproc, procfs_childpid_dir_name);
        exist_in_proc = 0;
        exist_in_proc_ret = ExistStartNumericInDir((char*)"/proc/", pid_string, &exist_in_proc);

        write_ret = write(fd_parent, &read_state, sizeof(read_state));
        if ((read_ret == -1) || (read_ret == 0))
        {
            DWARNING_MSG("t[%llu] - BruteForceGIDProcesses broken read fd_child pipe with child!! the GID range of this thread will be stopped...\n", (unsigned long long) pthread_self());
            break;
        }
        if ((write_ret == -1) || (write_ret == 0))
        {
            DWARNING_MSG("t[%llu] - BruteForceGIDProcesses broken write fd_parent pipe with child!! the GID range of this thread will be stopped... \n", (unsigned long long) pthread_self());
            break;
        }

        rootkit_msg_detection = CheckRootkitProcessesGID(exist_in_proc_ret, exist_in_proc, proc_ret, gid_from_proc, statproc_ret, gid_from_statproc, gid_detected, actual_gid, last_gid);
        if (rootkit_msg_detection != NULL)
        {
            RootkitDetected((char*)"BruteForceGIDProcesses", rootkit_msg_detection, th_dat);
            free(rootkit_msg_detection);
            rootkit_msg_detection = NULL;

            break;
        }

        if (th_dat->arguments->disable_each_display == 0)
        {
            ShowEachDisplay(&i, &remain, &tv1, (char*) "BruteForceGIDProcesses", actual_gid, th_dat->last_gid);
        }

    } while (actual_gid++ != th_dat->last_gid);
}

void _Child(int fd_child, int fd_parent, THD_DAT_t* th_dat)
{
    ssize_t write_ret = 0;
    ssize_t read_ret = 0;
    int set_gid_ret = 0;
    unsigned int gid_detected = 0;
    unsigned int last_gid = 0;
    unsigned int actual_gid = 0;
    int read_state = 0;
    unsigned int gid_aux = 0;

    actual_gid = th_dat->first_gid;
    do
    {
        gid_detected = 0;
        set_gid_ret = setgid(actual_gid);
        last_gid = gid_detected;
        gid_detected = getgid();

        write_ret = write(fd_child, &gid_detected, sizeof(gid_detected));
        read_ret = read(fd_parent, &read_state, sizeof(read_state));

        if ((write_ret == 0) || (write_ret == -1))
        {
            break;
        }
        if ((read_ret == 0) || (read_ret == -1))
        {
            break;
        }

        if ((actual_gid != gid_detected) ||
                (last_gid == gid_detected) ||
                (set_gid_ret != 0))
        {
            /* possible rootkit detected */
            gid_aux = 0;
            write(fd_child, &gid_aux, sizeof(gid_aux));

            break;
        }
    } while (actual_gid++ != th_dat->last_gid);
}


void Parent(pid_t child_pid, char* fifo_child, char* fifo_parent, THD_DAT_t* th_dat)
{
    int fd_child = 0;
    int fd_parent = 0;

    fd_child = open(fifo_child, O_RDONLY);
    if (fd_child != -1)
    {
        fd_parent = open(fifo_parent, O_WRONLY);
        if (fd_parent != -1)
        {
            _Parent(child_pid, fd_child, fd_parent, th_dat);

            close(fd_parent);
        }
        close(fd_child);
    }
}

void Child(char* fifo_child, char* fifo_parent, THD_DAT_t* th_dat)
{
    int fd_child = 0;
    int fd_parent = 0;

    fd_child = open(fifo_child, O_WRONLY);
    if (fd_child != -1)
    {
        fd_parent = open(fifo_parent, O_RDONLY);
        if (fd_parent != -1)
        {
            _Child(fd_child, fd_parent, th_dat);

            close(fd_parent);
        }
        close(fd_child);
    }
}

void* BruteForceGIDProcesses(void* arg)
{
    THD_DAT_t* th_dat = (THD_DAT_t*)arg;
    char fifo_name[PATH_MAX];
    char fifo_parent[PATH_MAX];
    char fifo_child[PATH_MAX];
    pid_t child_pid;

    memset(fifo_name, 0, sizeof(fifo_name));
    memset(fifo_parent, 0, sizeof(fifo_parent));
    memset(fifo_child, 0, sizeof(fifo_child));

    sprintf(fifo_name, "%llu", (unsigned long long) pthread_self());

    sprintf(fifo_parent, "%s/%s.parent_processes", th_dat->tmp_dir, fifo_name);
    sprintf(fifo_child, "%s/%s.child_processes", th_dat->tmp_dir, fifo_name);

    DOK_MSG("t[%llu] - BruteForceGIDProcesses New thread! GID range: %u - %u\n\t%s \n\t%s\n", (unsigned long long) pthread_self(), th_dat->first_gid, th_dat->last_gid, fifo_parent, fifo_child);

    if (mkfifo(fifo_parent, 0666) == 0)
    {
        if (mkfifo(fifo_child, 0666) == 0)
        {
            child_pid = fork();
            if (child_pid != -1)
            {
                if (child_pid == 0)
                {
                    Child(fifo_child, fifo_parent, th_dat);
                }
                else
                {
                    Parent(child_pid, fifo_child, fifo_parent, th_dat);
                }
            }
            unlink(fifo_child);
        }
        unlink(fifo_parent);
    }

    return NULL;
}

void* BruteForceKillProcesses(void* arg)
{
    THD_DAT_t* th_dat = (THD_DAT_t*)arg;
    pid_t child_pid;
    unsigned int actual_signal = 0;
    char pid_string[PATH_MAX];
    char detection_msg[PATH_MAX];
    int exist = 0;
    int exist_ret = 0;
    unsigned int i = 0;
    unsigned int remain = 0;
    struct timeval tv1;

    DOK_MSG("t[%llu] - BruteForceKillProcesses New thread! Signal range: %u - %u\n", (unsigned long long) pthread_self(), th_dat->first_gid, th_dat->last_gid);

    child_pid = fork();
    if (child_pid == 0)
    {
        while (1)
        {
            sleep(1);
        }
    }
    else
    {
        gettimeofday(&tv1, NULL);

        i = 0;
        actual_signal = th_dat->first_gid;
        remain = 0;
        memset(pid_string, 0, sizeof(pid_string));
        sprintf(pid_string, "%d", child_pid);
        do
        {
            if ((actual_signal >= 1) && (actual_signal <= SIGUNUSED))
            {
                printf("t[%llu] - skipping signal: %d\n", (unsigned long long) pthread_self(), actual_signal);
            }
            else
            {
                kill(child_pid, actual_signal);
                exist = 0;
                exist_ret = 0;
                exist_ret = ExistFileInDir((char*)"/proc", pid_string, &exist);
                if ((exist_ret == -1) || (exist == 0))
                {
                    memset(detection_msg, 0, sizeof(detection_msg));
                    sprintf(detection_msg, "process hidding via: kill signal: %u", actual_signal);
                    RootkitDetected((char*)"BruteForceKillProcesses", detection_msg, th_dat);
                    break;
                }

                if (th_dat->arguments->disable_each_display == 0)
                {
                    ShowEachDisplay(&i, &remain, &tv1, (char*) "BruteForceKillProcesses", actual_signal, th_dat->last_gid);
                }
            }
        } while (actual_signal++ != th_dat->last_gid);

        kill(child_pid, SIGKILL);
    }

    return NULL;
}

const char* argp_program_version = "lsrootkit beta0.1";
const char* argp_program_bug_address = "dreg@fr33project.org";

static char doc[] =
    "lsrootkit options (all analysis are ON by default):\
\v-";

static char args_doc[] = " ";

enum CMD_OPT_e
{
    OPT_EMPTY = 1,
    OPT_TMP_PATH,
    OPT_REPORT_PATH,
    OPT_DISABLE_EACH_DISPLAY,
    OPT_DISABLE_COLORS,
    OPT_ONLY_PROCESSES_GID,
    OPT_ONLY_FILES_GID,
    OPT_ONLY_PROCESSES_KILL,
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
static struct argp_option options[] =
{
    {
        "tmp-path", OPT_TMP_PATH, "FILE", OPTION_ARG_OPTIONAL,
        "Set new temp path dir. Example: --tmp-path=/var/tmp"
    },
    {
        "report-path", OPT_REPORT_PATH, "FILE", OPTION_ARG_OPTIONAL,
        "Set new report path. it needs also the name. Example: --report-path=/root/analysis.txt"
    },
    { "disable-each-display", OPT_DISABLE_EACH_DISPLAY, 0, OPTION_ARG_OPTIONAL, "Disable each display messages" },
    { "disable-colors", OPT_DISABLE_COLORS, 0, OPTION_ARG_OPTIONAL, "Disable colours in output" },
    { "only-gid-processes", OPT_ONLY_PROCESSES_GID, 0, OPTION_ARG_OPTIONAL, "Only bruteforce processes GID" },
    { "only-gid-files", OPT_ONLY_FILES_GID, 0, OPTION_ARG_OPTIONAL, "Only bruteforce files GID" },
    { "only-kill-processes", OPT_ONLY_PROCESSES_KILL, 0, OPTION_ARG_OPTIONAL, "Only bruteforce processes Kill" },

    { 0 }
};
#pragma GCC diagnostic pop


static error_t parse_opt(int key, char* arg, struct argp_state* state)
{
    struct arguments* arguments = (struct arguments*) state->input;

    switch (key)
    {
    case OPT_TMP_PATH:
        arguments->tmp_path = arg;
        break;

    case OPT_REPORT_PATH:
        arguments->report_path = arg;
        break;

    case OPT_DISABLE_EACH_DISPLAY:
        arguments->disable_each_display = 1;
        break;

    case OPT_DISABLE_COLORS:
        arguments->disable_colors = 1;
        break;

    case OPT_ONLY_PROCESSES_GID:
        arguments->only_processes_gid = 1;
        break;

    case OPT_ONLY_PROCESSES_KILL:
        arguments->only_processes_kill = 1;
        break;

    case OPT_ONLY_FILES_GID:
        arguments->only_files_gid = 1;
        break;

    case ARGP_KEY_ARG:
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
static struct argp argp = { options, parse_opt, args_doc, doc };
#pragma GCC diagnostic pop

int mainw(struct arguments* arguments);

int main(int argc, char* argv[])
{
    struct arguments arguments;

    memset(&arguments, 0, sizeof(arguments));

    arguments.tmp_path = NULL;
    arguments.report_path = NULL;
    arguments.disable_each_display = 0;
    arguments.only_processes_gid = 0;
    arguments.only_files_gid = 0;
    arguments.only_processes_kill = 0;
    arguments.disable_colors = 0;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    disable_colors = arguments.disable_colors;

    DRAW_MSG(" \n--\n"
             "%s%s - Rootkit Detector for UNIX\n%s"
             "-\n"
             "MIT LICENSE - Copyright(c) 2013\n"
             "by David Reguera Garcia aka Dreg - dreg@fr33project.org\n"
             "https://github.com/David-Reguera-Garcia-Dreg\n"
             "http://www.fr33project.org\n"
             "-\n"
             "For program help type: %s --help\n"
             "-\n"
             "Features:\n"
             "\t - Processes:\n"
             "\t\t - Full GIDs process occupation (processes GID bruteforcing)\n"
             "\t\t - Full Kill Signal process occupation (processes Kill bruteforcing)\n"
             "\t - Files: Full GIDs file occupation (files GID bruteforcing)\n"
             "\n"
             "%sWarning!!: each analysis-feature can take: %s.\n%s"
             "\n"
             "%sVery Important: if lsrootkit process crash you can have a rootkit in the system with some bugs: memory leaks etc.\n%s"
             "--\n\n"
             ,
             disable_colors == 0 ? _PCCYN : "",
             argp_program_version,
             disable_colors == 0 ? _PCRESET : "",
             argv[0],
             disable_colors == 0 ? _PCRED : "",
             SPEED_TEST,
             disable_colors == 0 ? _PCRESET : "",
             disable_colors == 0 ? _PCYEL : "",
             disable_colors == 0 ? _PCRESET : ""
            );

    return mainw(&arguments);
}

int RunAnalysis(THD_DAT_t* thread_data, THREAD_FUNC_t analysis_func)
{
    int detected = 0;
    pthread_t threads[NUM_THREADS];
    int t;

    memset(threads, 0, sizeof(threads));

    for (t = 0; t < NUM_THREADS; t++)
    {
        pthread_create(&(threads[t]), NULL, analysis_func, (void*)(thread_data + t));
    }

    detected = 0;
    for (t = 0; t < NUM_THREADS; t++)
    {
        pthread_join(threads[t], NULL);
        if ((thread_data + t)->detected != 0)
        {
            detected = 1;
        }
    }

    return detected;
}


int mainw(struct arguments* arguments)
{
    char* dir_name = NULL;
    THD_DAT_t th_dat[NUM_THREADS];
    int t;
    unsigned int actual_first_gid = 0;
    unsigned int distance_between_gids = (MAX_VALUE(gid_t) / NUM_THREADS);
    char report_path[PATH_MAX];
    char report_path_time[PATH_MAX];
    FILE* file_report = NULL;
    int detected = 0;
    pthread_mutex_t mutex;
    THREAD_FUNC_t anal_funcs[4];
    char str_date[256];
    time_t rawtime;
    struct tm* timeinfo;

    pthread_mutex_init(&mutex, NULL);

    memset(th_dat, 0, sizeof(th_dat));
    memset(report_path, 0, sizeof(report_path));

    if (arguments->tmp_path == NULL)
    {
        dir_name = CreateTempDir();
    }
    else
    {
        dir_name = arguments->tmp_path;
    }

    DOK_MSG("tmp path: %s\n", dir_name);

    if (CheckRights(dir_name) == 0)
    {
        if (arguments->report_path == NULL)
        {
            if (getcwd(report_path, sizeof(report_path)) == NULL)
            {
                report_path[0] = '.';
            }
            if (report_path[0] == '(')
            {
                perror(report_path);
                memset(report_path, 0, sizeof(report_path));
                report_path[0] = '.';
            }

            strcat(report_path, "/lsrootkit_report");

            do
            {
                memset(report_path_time, 0, sizeof(report_path_time));
                sprintf(report_path_time, "%s_%llu", report_path, (unsigned long long) time(NULL));
                DINFO_MSG("Trying open report path: %s\n", report_path_time);
                file_report = fopen(report_path_time, "wb+");
                if (NULL == file_report)
                {
                    DERROR_MSG("oppening: %s\n", report_path_time);
                    perror("");
                    sleep(1);
                }
            } while (NULL == file_report);
        }
        else
        {
            memset(report_path_time, 0, sizeof(report_path_time));
            strcpy(report_path_time, arguments->report_path);
            file_report = fopen(report_path_time, "wb+");
        }

        if (file_report == NULL)
        {
            DERROR_MSG("openning file report: %s\n", report_path_time);
            perror("");
        }
        else
        {
            DOK_MSG("Report path Open: %s\n", report_path_time);

            DINFO_MSG("Static info:\n\tNumber of threads: %d\n\tEach display msg interval: %d\n\tGID range: 1 - %llu\n\tMax bytes reserved to found GID entry in /proc/pid/status: %u \n\n", NUM_THREADS, EACH_DISPLAY, MAX_VALUE(gid_t), PROC_GID_BYTES);

            time(&rawtime);
            timeinfo = localtime(&rawtime);
            memset(str_date, 0, sizeof(str_date));
            strftime(str_date, sizeof(str_date), "%c", timeinfo);
            DINFO_MSG("Start analysis date: %s\n\n", str_date);

            for (t = 0; t < NUM_THREADS; t++)
            {
                th_dat[t].arguments = arguments;
                th_dat[t].mutex = &mutex;
                th_dat[t].report_path = file_report;
                th_dat[t].tmp_dir = dir_name;
                th_dat[t].first_gid = actual_first_gid + 1;
                actual_first_gid += distance_between_gids;
                th_dat[t].last_gid = actual_first_gid;
                if ((t + 1) == NUM_THREADS)
                {
                    th_dat[t].last_gid = MAX_VALUE(gid_t);
                }
                DINFO_MSG("Thread: %d, GID/Signal range: %u - %u\n", t + 1, th_dat[t].first_gid, th_dat[t].last_gid);
            }

            puts("\n");

            memset(anal_funcs, 0, sizeof(anal_funcs));
            t = 0;
            if (arguments->only_files_gid)
            {
                anal_funcs[t] = BruteForceGIDFiles;
            }
            else if (arguments->only_processes_gid)
            {
                anal_funcs[t] = BruteForceGIDProcesses;
            }
            else if (arguments->only_processes_kill)
            {
                anal_funcs[t] = BruteForceKillProcesses;
            }
            else
            {
                anal_funcs[t++] = BruteForceGIDProcesses;
                anal_funcs[t++] = BruteForceGIDFiles;
                anal_funcs[t++] = BruteForceKillProcesses;
            }

            detected = 0;
            for (t = 0; (unsigned int)t < MYARRAYSIZE(anal_funcs); t++)
            {
                if (anal_funcs[t] != NULL)
                {
                    if (RunAnalysis((THD_DAT_t*)&th_dat, anal_funcs[t]) == 1)
                    {
                        detected = 1;
                        break;
                    }
                }
            }

            DINFO_MSG("Result Analysis: %s\n\n", report_path_time);
            fprintf(file_report, "\n\nResult Analysis: \n\n");
            if (detected != 0)
            {
                DDETECTED_MSG("WARNING!!! POSSIBLE ROOTKIT DETECTED!!\n\n");
                fprintf(file_report, "\n\nWARNING!!! POSSIBLE ROOTKIT DETECTED!!\n\n");
            }
            else
            {
                DNODETECTED_MSG("OK - NO ROOTKITS DETECTED\n\n");
                fprintf(file_report, "\n\nOK - NO ROOTKITS DETECTED\n\n");
            }

            fflush(file_report);

            fclose(file_report);

            pthread_mutex_destroy(&mutex);

            DINFO_MSG("Start analysis date: %s\n", str_date);
            time(&rawtime);
            timeinfo = localtime(&rawtime);
            memset(str_date, 0, sizeof(str_date));
            strftime(str_date, sizeof(str_date), "%c", timeinfo);
            DINFO_MSG("End analysis date: %s\n", str_date);
        }
    }
    else
    {
        DERROR_MSG("the process have not rights, run it as root or set the caps for: stat, chown, setgid & access to /proc\n\n");
    }

    DINFO_MSG("Deleting temp dir: %s\n\n", dir_name);
    rmdir(dir_name);

    return 0;
}

char* CreateTempDir(void)
{
    char* tmp_path = NULL;
    char template_tmp[PATH_MAX];
    char* ret = NULL;

    memset(template_tmp, 0, sizeof(template_tmp));

    if (!(tmp_path = getenv("TMPDIR")))
    {
        if (!(tmp_path = getenv("TMP")))
        {
            if (!(tmp_path = getenv("TEMP")))
            {
                if (!(tmp_path = getenv("TEMPDIR")))
                {
                    tmp_path = (char*) "/tmp";
                }
            }
        }
    }

    if (NULL == tmp_path)
    {
        DERROR_MSG( "NULL TEMP PATH\n");
        return NULL;
    }

    DINFO_MSG("TEMP DIR: %s\n", tmp_path);

    if ((strlen(tmp_path) + sizeof(LSROOT_TMP_TEMPLATE)) > sizeof(template_tmp))
    {
        DERROR_MSG("TOO BIG SIZE TEMP PATH\n");
        return NULL;
    }

    strcpy(template_tmp, tmp_path);
    strcat(template_tmp, LSROOT_TMP_TEMPLATE);

    char* dir_name = mkdtemp(template_tmp);
    if (dir_name == NULL)
    {
        DERROR_MSG("mkdtemp failed");
        return NULL;
    }

    ret = (char*)calloc(1, strlen(dir_name) + 1);
    strcpy(ret, dir_name);

    return ret;
}


/*
Dreg notes:

ps aux | grep main  | cut -d ' ' -f6 | xargs kill -9 ; ps aux | grep main ; rm -rf ./main* && cp ./projects/newlsrootkit/main.cpp ./main.c && gcc -pedantic -Wall -Wextra -x c -std=c99 -lpthread -o main main.c && ./main --only-processes-gid


lsof -ai -g -p2068

*/
