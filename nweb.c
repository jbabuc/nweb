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

#define BUFSIZE 1024 * 1000
#define FORBIDDEN 403
#define NOTFOUND 404

#define STR_TIME ctime(localtime())
#define KEEPALIVE 1
#define RECEIVE_TIMEOUT_SEC 10

#define PRINT_LOG(str_format, ...)                                  \
    {                                                               \
        time_t curtime = time(NULL);                                \
        struct tm* ltm = localtime(&curtime);                       \
        printf("[%d-%02d-%02d %02d:%02d:%02d] " str_format,         \
            ltm->tm_year + 1900, ltm->tm_mon + 1, ltm->tm_mday,     \
            ltm->tm_hour, ltm->tm_min, ltm->tm_sec, ##__VA_ARGS__); \
    \
}

// input and output could be same array, for output will be smaller than input
void url_decode(const char* input, char* output)
{
    while (*input) {
        if (*input == '%') {
            char b[3] = { input[1], input[2], 0 };
            *output++ = strtol(b, NULL, 16);
            input += 3;
        }
        else {
            *output++ = *input++;
        }
    }
    *output = 0; // null terminate
}

void send_error(int socketfd, int http_ret_code, char* http_msg, char* bigbuffer)
{
    PRINT_LOG("[%d] Error return, %d, %s\n", getpid(), http_ret_code, http_msg);
    sprintf(bigbuffer, "HTTP/1.1 %d\nContent-Length: %d\nContent-Type: text/html\n\n%s", http_ret_code, strlen(http_msg), http_msg);
    write(socketfd, bigbuffer, strlen(bigbuffer));
}

void listdir(char* str_dirname, int socketfd, char* bigbuffer)
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

    char buffer[2048];

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
    sprintf(buffer, "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><head><style>td { padding: 0 10; }</style></head><body style=\"font-family: consolas\"><table border=0>\n");
    write(socketfd, buffer, strlen(buffer));

    int bigbuffer_pos = 0;
    char str_fsize[16];

    for (i = 0; i < nfiles; i++) {
        // puts(arr_files[i]->name);

        if (arr_files[i]->s.st_mode & S_IFDIR) {
            str_fsize[0] = 0;
        }
        else {
            int fsize = arr_files[i]->s.st_size / 1024;
            sprintf(str_fsize, "%d%s", fsize > 0 ? fsize : arr_files[i]->s.st_size, fsize > 0 ? "kb" : "b");
        }

        sprintf(buffer, "<tr><td>%s</td><td>%s</td><td><a href=\"./%s\">%s</a></td></tr>\n", ctime(&(arr_files[i]->s.st_mtime)), str_fsize, arr_files[i]->name, arr_files[i]->name);

        int blen = strlen(buffer);
        if (bigbuffer_pos + blen >= BUFSIZE) {
            if (write(socketfd, bigbuffer, strlen(bigbuffer)) < 0) { // error, probably closed connection
                PRINT_LOG("Write error. Probably closed connection, ignore\n");
                break;
            }
            bigbuffer_pos = 0;
        }
        sprintf(&bigbuffer[bigbuffer_pos], "%s", buffer);
        bigbuffer_pos += blen;
    }
    write(socketfd, bigbuffer, strlen(bigbuffer));
    sprintf(buffer, "</table></body></html>");
    write(socketfd, buffer, strlen(buffer));

    for (i = 0; i < nfiles; i++) {
        free(arr_files[i]); // free memory
    }

    closedir(dp);
}

/* this is a child web server process, so we can exit on errors */
void web(int socketfd)
{
    struct timeval tv;
    tv.tv_sec = RECEIVE_TIMEOUT_SEC;
    tv.tv_usec = RECEIVE_TIMEOUT_SEC * 1000;
    // code supports only GET, so, no need for extensive receive time
    if (setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        PRINT_LOG("[%d] Error setting socket receive timeout.", getpid());
    }

    char buffer[BUFSIZE + 1];
    while (KEEPALIVE) {
        {
            // read socket
            long ret = read(socketfd, buffer, BUFSIZE); /* read Web request in one go */
            if (ret > 0 && ret < BUFSIZE) {
                buffer[ret] = 0; /* terminate the buffer */
            }
            else {
                break;
            }
        }

        // PRINT_LOG("[%d] Full request, \n---------------------%s---------------------\n", getpid(), buffer);
        if (strncmp(buffer, "GET ", 4) && strncmp(buffer, "get ", 4)) {
            send_error(socketfd, FORBIDDEN, "Only GET is supported", buffer);
            continue;
        }

        { // keep only url
            int i;
            for (i = 4; i < BUFSIZE; i++) {
                if (buffer[i] == ' ') {
                    buffer[i] = 0;
                    break;
                }
            }
        }

        url_decode(buffer[4] == '/' ? &buffer[5] : &buffer[4], buffer);

        { //check for illegal parent directory use ..
            int i = 0, n = strlen(buffer);
            for (i = 0; i < n - 1; i++) {
                if (buffer[i] == '.' && buffer[i + 1] == '.') {
                    send_error(socketfd, FORBIDDEN, "Parent directory (..) path names not supported", buffer);
                    continue;
                }
            }
        }

        /* 5th char is a slash, ignore it */
        if (strlen(buffer) == 0)
            strcpy(buffer, ".");

        PRINT_LOG("[%d] Requested, %s\n", getpid(), buffer);

        struct stat s;
        if (stat(buffer, &s) == 0) { /* file found */
            if (s.st_mode & S_IFDIR) { /* directory */
                listdir(buffer, socketfd, buffer);
                // content length unknown, so, exit socket. else, client will not know if stream ended.
                break;
            }
            else { /* file */
                int file_fd = open(buffer, O_RDONLY | O_NONBLOCK);
                if (file_fd < 0) {
                    send_error(socketfd, NOTFOUND, "Not Found", buffer);
                    continue;
                }

                long len = (long)lseek(file_fd, (off_t)0, SEEK_END); /* lseek to the file end to find the length */
                lseek(file_fd, (off_t)0, SEEK_SET); /* lseek back to the file start ready for reading */
                sprintf(buffer, "HTTP/1.1 200 OK\nServer: nweb\nContent-Length: %ld\n\n", len);
                // PRINT_LOG("Header: HTTP/1.1 200 OK\nServer: nweb\nContent-Length: %ld\n\n", len);
                write(socketfd, buffer, strlen(buffer));

                /* send file in buffer size block - last block may be smaller */
                int nread;
                while ((nread = read(file_fd, buffer, BUFSIZE)) > 0) {
                    if (write(socketfd, buffer, nread) < 0) { // error, probably closed connection
                        PRINT_LOG("Write error. Probably closed connection, ignore and exit\n ");
                        break;
                    }
                }
                close(file_fd);
                sleep(1);
            }
        }
        else { /* file not found */
            send_error(socketfd, NOTFOUND, "Not Found", buffer);
            continue;
        }
    }

    // PRINT_LOG("[%d] Child exiting...\n", getpid());
    shutdown(socketfd, SHUT_WR);
    close(socketfd);
    exit(0);
}

int main(int argc, char** argv)
{
    int i, pid, listenfd, socketfd;
    static struct sockaddr_in cli_addr; /* static = initialised to zeros */
    static struct sockaddr_in serv_addr; /* static = initialised to zeros */

    if (argc < 3 || argc > 3 || !strcmp(argv[1], "-?")) {
        PRINT_LOG("\thint: nweb Port-Number Top-Directory\n"
                  "\tnweb is a small and very safe mini web server\n"
                  "\tserves only from the named directory or its sub-directories\n"
                  "\tThere is no fancy features = safe and secure\n\n"
                  "\tExample: nweb 8181 /home/nwebdir\n\n");

        PRINT_LOG("\tNot Supported: directories / /etc /bin /lib /tmp /usr /dev /sbin \n"
                  "\tNo warranty given or implied, Nigel Griffiths nag@uk.ibm.com\n"
                  "\tDirectory listing function added by Janardhan Babu Chinta\n");
        exit(0);
    }
    if (!strncmp(argv[2], "/", 2) || !strncmp(argv[2], "/etc", 5) || !strncmp(argv[2], "/bin", 5) || !strncmp(argv[2], "/lib", 5) || !strncmp(argv[2], "/tmp", 5) || !strncmp(argv[2], "/usr", 5) || !strncmp(argv[2], "/dev", 5) || !strncmp(argv[2], "/sbin", 6)) {
        PRINT_LOG("ERROR: Bad top directory %s, see nweb -?\n", argv[2]);
        exit(3);
    }
    if (chroot(argv[2]) == -1) {
        PRINT_LOG("ERROR: Can't root to directory %s\n", argv[2]);
        if (chdir(argv[2]) == -1) {
            PRINT_LOG("ERROR: Can't Change to directory %s\n", argv[2]);
            exit(4);
        }
    }

    signal(SIGCHLD, SIG_IGN); /* let kernel automatically reap children */
    setpgrp(); /* break away from process group */
    /* setup the network socket */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        PRINT_LOG("Error creating socket\n");
        exit(6);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1]));
    if (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        PRINT_LOG("Error binding socket to port, %s\n", argv[1]);
        exit(6);
    }

    if (listen(listenfd, 64) < 0) {
        PRINT_LOG("Error listening to port, %s\n", argv[1]);
        exit(7);
    }

    PRINT_LOG("nweb started at port %s, pid %d\n", argv[1], getpid());

    while (1) {
        socklen_t length = sizeof(cli_addr);

        if ((socketfd = accept(listenfd, (struct sockaddr*)&cli_addr, &length)) < 0) {
            PRINT_LOG("Accept error\n");
        }

        if ((pid = fork()) < 0) {
            PRINT_LOG("Fork error\n");
        }
        else {
            if (pid == 0) { /* child */
                PRINT_LOG("[%d] Serving client, %s:%d\n", getpid(), inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
                close(listenfd); // child has no use with server socket
                web(socketfd); /* never returns, serves request and exits */
            }
            else { /* parent */
                close(socketfd); // parent has no use with client socket
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
CMD /run.sh

run.sh-------------
/nwebs 3140 /webroot /webroot/nweb.log
cp /nwebs /webroot/
sleep 5000

Executed below commands-------------
docker build -t nwebs:1
docker run -v /root:/webroot nwebs:1 &
docker exec -it containerid sh
nwebs is copied /root. downloaded on browser
*/
