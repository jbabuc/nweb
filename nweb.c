#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <time.h>
#include <stdlib.h>

#define VERSION 23
#define BUFSIZE 1024 * 1000
#define ERROR 42
#define LOG 44
#define FORBIDDEN 403
#define NOTFOUND 404

#ifndef SIGCLD
#define SIGCLD SIGCHLD
#endif

char* LOGFILE;

void logger(int type, char* s1, char* s2, int socket_fd)
{
    int fd;
    char logbuffer[BUFSIZE];

    switch (type) {
    case ERROR:
        (void)sprintf(logbuffer, "ERROR: %s:%s Errno=%d exiting pid=%d", s1, s2, errno, getpid());
        break;
    case FORBIDDEN:
        (void)write(socket_fd, "HTTP/1.1 403 Forbidden\nContent-Length: 185\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden</h1>\nThe requested URL, file type or operation is not allowed on this simple static file webserver.\n</body></html>\n", 271);
        (void)sprintf(logbuffer, "FORBIDDEN: %s:%s", s1, s2);
        break;
    case NOTFOUND:
        (void)write(socket_fd, "HTTP/1.1 404 Not Found\nContent-Length: 136\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\nThe requested URL was not found on this server.\n</body></html>\n", 224);
        (void)sprintf(logbuffer, "NOT FOUND: %s:%s", s1, s2);
        break;
    case LOG:
        (void)sprintf(logbuffer, "%s:%s:%d", s1, s2, socket_fd);
        break;
    }
    /* No checks here, nothing can be done with a failure anyway */
    if ((fd = open(LOGFILE, O_CREAT | O_WRONLY | O_APPEND, 0644)) >= 0) {
        (void)write(fd, logbuffer, strlen(logbuffer));
        (void)write(fd, "\n", 1);
        (void)close(fd);
    }
    if (type == ERROR || type == NOTFOUND || type == FORBIDDEN)
        exit(3);
}

void listdir(char* str_dirname, int fd, char* bigbuffer)
{
    struct myfile {
        struct stat s;
        char name[256];
        struct myfile* next;
    };

    int myfilecmp(const void* f1, const void* f2)
    {
        struct myfile** mf1 = (struct myfile**)f1;
        struct myfile** mf2 = (struct myfile**)f2;

        // both are directories, do strcmp
        if (S_ISDIR((*mf1)->s.st_mode) && S_ISDIR((*mf2)->s.st_mode))
            return strcmp((*mf1)->name, (*mf2)->name);

        if (S_ISDIR((*mf1)->s.st_mode))
            return -1;
        if (S_ISDIR((*mf2)->s.st_mode))
            return 1;

        return (*mf2)->s.st_mtime - (*mf1)->s.st_mtime;
    }

    static char buffer[2048];

    DIR* dp;
    struct dirent* ep;

    dp = opendir(str_dirname);

    struct myfile* ll_files = NULL;
    struct myfile* current_file = NULL;
    int nfiles = 0;

    for (; ep = readdir(dp); nfiles++) {
        struct myfile* f = (struct myfile*)malloc(sizeof(struct myfile)); // allocate memory

        sprintf(buffer, "%s/%s", str_dirname, ep->d_name);
        stat(buffer, &f->s);
        (void)sprintf(f->name, "%s%s", ep->d_name, (f->s.st_mode & S_IFDIR) ? "/" : "");

        // build linked list
        if (ll_files == NULL) {
            ll_files = f;
        }
        else {
            current_file->next = f;
        }
        current_file = f;
    }

    // prepare array for qsort
    struct myfile* arr_files[nfiles];
    int i = 0;
    for (current_file = ll_files; current_file; current_file = current_file->next) {
        arr_files[i] = current_file;
        ++i;
    }

    // sort
    qsort(arr_files, nfiles, sizeof(void*), myfilecmp);

    // write
    (void)sprintf(buffer, "HTTP/1.1 200 OK\nServer: nweb/%d.0\nContent-Type: text/html\n\n<html><head><style>td { padding: 0 10; }</style><head><body style=\"font-family: consolas\"><table border=0>\n", VERSION);
    (void)write(fd, buffer, strlen(buffer));

    int bigbuffer_size = 0;
    for (i = 0; i < nfiles; i++) {
        // puts(arr_files[i]->name);

        char str_fsize[16];
        if (arr_files[i]->s.st_mode & S_IFDIR) {
            str_fsize[0] = 0;
        }
        else {
            int fsize = arr_files[i]->s.st_size / 1024;
            (void)sprintf(str_fsize, "%d%s", fsize > 0 ? fsize : arr_files[i]->s.st_size, fsize > 0 ? "kb" : "b");
        }

        (void)sprintf(buffer, "<tr><td>%s</td><td>%s</td><td><a href=\"./%s\">%s</a></td></tr>\n", ctime(&(arr_files[i]->s.st_mtime)), str_fsize, arr_files[i]->name, arr_files[i]->name);

        int blen = strlen(buffer);
        if (bigbuffer_size + blen >= BUFSIZE) {
            (void)write(fd, bigbuffer, strlen(bigbuffer));
            bigbuffer_size = 0;
        }
        sprintf(&bigbuffer[bigbuffer_size], "%s", buffer);
        bigbuffer_size += blen;
    }
    (void)write(fd, bigbuffer, strlen(bigbuffer));
    (void)sprintf(buffer, "</table></body></html>", VERSION);
    (void)write(fd, buffer, strlen(buffer));

    for (i = 0; i < nfiles; i++) {
        free(arr_files[i]); // free memory
    }

    (void)closedir(dp);
}

/* this is a child web server process, so we can exit on errors */
void web(int fd, int hit)
{
    int i, j;
    static char buffer[BUFSIZE + 1]; /* static so zero filled */

    long ret = read(fd, buffer, BUFSIZE); /* read Web request in one go */
    if (ret == 0 || ret == -1) { /* read failure stop now */
        logger(FORBIDDEN, "failed to read browser request", "", fd);
    }
    /* return code is valid chars */
    if (ret > 0 && ret < BUFSIZE)
        buffer[ret] = 0; /* terminate the buffer */
    else
        buffer[0] = 0;

    /* remove CF and LF characters */
    for (i = 0; i < ret; i++) {
        if (buffer[i] == '\r' || buffer[i] == '\n')
            buffer[i] = '*';
    }

    // logger(LOG, "FULL REQUEST", buffer, hit);
    if (strncmp(buffer, "GET ", 4) && strncmp(buffer, "get ", 4)) {
        logger(FORBIDDEN, "Only simple GET operation supported", buffer, fd);
    }
    for (i = 4; i < BUFSIZE; i++) { /* null terminate after the second space to ignore extra stuff */
        if (buffer[i] == ' ') { /* string is "GET URL " +lots of other stuff */
            buffer[i] = 0;
            break;
        }
    }

    /* check for illegal parent directory use .. */
    for (j = 0; j < i - 1; j++) {
        if (buffer[j] == '.' && buffer[j + 1] == '.') {
            logger(FORBIDDEN, "Parent directory (..) path names not supported", buffer, fd);
        }
    }

    logger(LOG, "REQUEST", buffer, hit);

    /* 5th char is a slash, ignore it */
    if (strlen(&buffer[5]) == 0)
        strcpy(&buffer[5], "./");
    char requested[strlen(&buffer[5]) + 1];
    strcpy(requested, &buffer[5]);

    struct stat s;
    if (stat(&buffer[5], &s) == 0) { /* file found */
        if (s.st_mode & S_IFDIR) { /* directory */
            listdir(&buffer[5], fd, buffer);
        }
        else { /* file */
            int file_fd = open(&buffer[5], O_RDONLY);
            int len = (long)lseek(file_fd, (off_t)0, SEEK_END); /* lseek to the file end to find the length */
            (void)lseek(file_fd, (off_t)0, SEEK_SET); /* lseek back to the file start ready for reading */
            (void)sprintf(buffer, "HTTP/1.1 200 OK\nServer: nweb/%d.0\nContent-Length: %ld\nConnection: close\n\n", VERSION, len); /* Header + a blank line */
            // logger(LOG, "Header ", buffer, hit);
            (void)write(fd, buffer, strlen(buffer));

            /* send file in buffer size block - last block may be smaller */
            while ((ret = read(file_fd, buffer, BUFSIZE)) > 0) {
                (void)write(fd, buffer, ret);
            }
        }

        sleep(1); /* allow socket to drain before signalling the socket is closed */
        close(fd);
        exit(1);
    }

    logger(NOTFOUND, "Failed to open file", &buffer[5], fd);
}

int main(int argc, char** argv)
{
    int i, port, pid, listenfd, socketfd, hit;
    socklen_t length;
    static struct sockaddr_in cli_addr; /* static = initialised to zeros */
    static struct sockaddr_in serv_addr; /* static = initialised to zeros */

    if (argc < 4 || argc > 4 || !strcmp(argv[1], "-?")) {
        (void)printf("\thint: nweb Port-Number Top-Directory LOGFILE\t\tversion %d\n\n"
                     "\tnweb is a small and very safe mini web server\n"
                     "\tserves only from the named directory or its sub-directories.\n"
                     "\tThere is no fancy features = safe and secure.\n\n"
                     "\tExample: nweb 8181 /home/nwebdir /home/logfile&\n\n",
            VERSION);

        (void)printf("\tNot Supported: directories / /etc /bin /lib /tmp /usr /dev /sbin \n"
                     "\tNo warranty given or implied\n\tNigel Griffiths nag@uk.ibm.com\n"
                     "\tDirectory listing function added by Janardhan Babu Chinta\n");
        exit(0);
    }
    if (!strncmp(argv[2], "/", 2) || !strncmp(argv[2], "/etc", 5) || !strncmp(argv[2], "/bin", 5) || !strncmp(argv[2], "/lib", 5) || !strncmp(argv[2], "/tmp", 5) || !strncmp(argv[2], "/usr", 5) || !strncmp(argv[2], "/dev", 5) || !strncmp(argv[2], "/sbin", 6)) {
        (void)printf("ERROR: Bad top directory %s, see nweb -?\n", argv[2]);
        exit(3);
    }
    LOGFILE = argv[3];
    if (chdir(argv[2]) == -1) {
        (void)printf("ERROR: Can't Change to directory %s\n", argv[2]);
        exit(4);
    }
    /* Become deamon + unstopable and no zombies children (= no wait()) */
    if (fork() != 0)
        return 0; /* parent returns OK to shell */
    (void)signal(SIGCLD, SIG_IGN); /* ignore child death */
    (void)signal(SIGHUP, SIG_IGN); /* ignore terminal hangups */
    for (i = 0; i < 32; i++)
        (void)close(i); /* close open files */
    (void)setpgrp(); /* break away from process group */
    logger(LOG, "nweb starting", argv[1], getpid());
    /* setup the network socket */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        logger(ERROR, "system call", "socket", 0);
    port = atoi(argv[1]);
    if (port < 0 || port > 60000)
        logger(ERROR, "Invalid port number (try 1->60000)", argv[1], 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);
    if (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
        logger(ERROR, "system call", "bind", 0);
    if (listen(listenfd, 64) < 0)
        logger(ERROR, "system call", "listen", 0);
    for (hit = 1;; hit++) {
        length = sizeof(cli_addr);
        if ((socketfd = accept(listenfd, (struct sockaddr*)&cli_addr, &length)) < 0)
            logger(ERROR, "system call", "accept", 0);
        if ((pid = fork()) < 0) {
            logger(ERROR, "system call", "fork", 0);
        }
        else {
            if (pid == 0) { /* child */
                (void)close(listenfd);
                web(socketfd, hit); /* never returns */
            }
            else { /* parent */
                (void)close(socketfd);
            }
        }
    }
}

/* 
built static executable in docker labs using below docker file

dockerfile------------
FROM gcc:4.9
COPY nweb.c /nweb.c
COPY run.sh /run.sh
RUN chmod +x /run.sh
RUN gcc -static -o /nwebs nweb.c
CMD /run.s

run.sh-------------
/nwebs 3140 /webroot /webroot/nweb.log
sleep 5000

Executed below commands
	docker build -t nwebs:1
	docker run -v /root:/webroot nwebs:1 &
	docker exec -it containerid sh
	copied the nwebs from container / to /webroot which is docker lab server /root and downloaded /root/nwebs on browser
*/
