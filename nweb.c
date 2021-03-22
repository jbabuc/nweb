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
#include <stdarg.h>

#define BUFSIZE 1024 * 1000
#define FORBIDDEN 403
#define NOTFOUND 404

#define KEEPALIVE 1
#define RECEIVE_TIMEOUT_SEC 10

#define PRINT_LOG(str_format, ...)                                            \
    {                                                                         \
        time_t curtime = time(NULL);                                          \
        struct tm* ltm = localtime(&curtime);                                 \
        printf("%d-%02d-%02d %02d:%02d:%02d [%d] " str_format,                \
            ltm->tm_year + 1900, ltm->tm_mon + 1, ltm->tm_mday,               \
            ltm->tm_hour, ltm->tm_min, ltm->tm_sec, getpid(), ##__VA_ARGS__); \
    \
}

#define INFO_LOG(str_format, ...)            \
    if (APP_LOG_LEVEL > 0) {                 \
        PRINT_LOG(str_format, ##__VA_ARGS__) \
    }

#define DEBUG_LOG(str_format, ...)           \
    if (APP_LOG_LEVEL > 1) {                 \
        PRINT_LOG(str_format, ##__VA_ARGS__) \
    }

int APP_LOG_LEVEL = 1;

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

void write_data(int socketfd, char* data, int length)
{
    DEBUG_LOG("Writing data %d bytes: \n---------------------\n%s\n---------------------\n", length, data);
    write(socketfd, data, length);
}

void send_error(int socketfd, int http_ret_code, char* http_msg, char* bigbuffer)
{
    INFO_LOG("Error return, %d, %s\n", http_ret_code, http_msg);
    sprintf(bigbuffer, "HTTP/1.1 %d\nContent-Length: %d\nContent-Type: text/html\n\n%s", http_ret_code, strlen(http_msg), http_msg);
    write_data(socketfd, bigbuffer, strlen(bigbuffer));
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
    long filename_content_size = 0;

    for (; ep = readdir(dp); nfiles++) {
        struct myfile* f = (struct myfile*)malloc(sizeof(struct myfile)); // allocate memory

        sprintf(buffer, "%s/%s", str_dirname, ep->d_name);
        stat(buffer, &f->s);
        filename_content_size += sprintf(f->name, "%s%s", ep->d_name, (f->s.st_mode & S_IFDIR) ? "/" : "");

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
    for (current_file = ll_files; current_file && i < nfiles; current_file = current_file->next, ++i) {
        arr_files[i] = current_file;
    }

    // sort
    qsort(arr_files, nfiles, sizeof(void*), myfilecmp);

    // write
    sprintf(buffer, "HTTP/1.1 200 OK\nContent-Length: %ld\nContent-Type: text/html\n\n\n", 350 + 22 + 105 * nfiles + filename_content_size);
    write_data(socketfd, buffer, strlen(buffer));

    int bigbuffer_pos = 0;
    char str_fsize[16];
    int line_len;

    void bufferOrWrite(int socketfd, char* buffer, char* bigbuffer, int* bigbuffer_pos)
    {
        DEBUG_LOG("bigbuffer_pos content length...%s... %d\n", buffer != NULL ? buffer : "null", *bigbuffer_pos);

        int line_len = buffer == NULL ? 0 : strlen(buffer);

        if (buffer == NULL || *bigbuffer_pos + line_len >= BUFSIZE) {
            write_data(socketfd, bigbuffer, *bigbuffer_pos);
            *bigbuffer_pos = 0;
        }
        if (buffer != NULL) {
            sprintf(&bigbuffer[*bigbuffer_pos], "%s", buffer);
            *bigbuffer_pos += line_len;
        }
    }

    // 350 chars
    sprintf(buffer, "<html><head><style>a:link { text-decoration: none; color: blue;} a:visited { text-decoration: none; color: blue;} a:hover { text-decoration: none; color: brown; } td { padding: 0 10; } body { font-family: consolas; } tr:hover {background-color:#e5e5e5;}</style><script>function f(a){window.location.href=a.text;}</script></head><body><table border=0>");
    bufferOrWrite(socketfd, buffer, bigbuffer, &bigbuffer_pos);

    for (i = 0; i < nfiles; i++) {
        // puts(arr_files[i]->name);

        if (arr_files[i]->s.st_mode & S_IFDIR) {
            str_fsize[0] = 0;
        }
        else {
            int fsize = arr_files[i]->s.st_size / 1024;
            sprintf(str_fsize, "%d%s", fsize > 0 ? fsize : arr_files[i]->s.st_size, fsize > 0 ? "kb" : "b");
        }

        struct tm* ltm = localtime(&(arr_files[i]->s.st_mtim.tv_sec));
        // 105 chars
        sprintf(buffer, "<tr><td>%d-%02d-%02d %02d:%02d:%02d</td><td>%16s</td><td><a href=\"#\" onclick=\"f(this)\">%s</a></td></tr>",
            ltm->tm_year + 1900, ltm->tm_mon + 1, ltm->tm_mday, ltm->tm_hour, ltm->tm_min, ltm->tm_sec,
            str_fsize, arr_files[i]->name);

        bufferOrWrite(socketfd, buffer, bigbuffer, &bigbuffer_pos);
    }
    // 22 chars
    sprintf(buffer, "</table></body></html>");
    bufferOrWrite(socketfd, buffer, bigbuffer, &bigbuffer_pos);
    bufferOrWrite(socketfd, NULL, bigbuffer, &bigbuffer_pos); // nothing else to buffer write

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
        PRINT_LOG("Error setting socket receive timeout.");
    }

    char buffer[BUFSIZE + 1];
    while (KEEPALIVE) {

        {
            long ret = read(socketfd, buffer, 4); // read 1st 4 chars
            if (ret < 1)
                break;
            if (strncmp(buffer, "GET ", 4) && strncmp(buffer, "get ", 4)) {
                send_error(socketfd, FORBIDDEN, "Only GET is supported", buffer);
                sleep(5); // avoid spam
                break; // not a get request, exit
            }
        }

        {
            long ret = read(socketfd, buffer, 2050); // read max get request size 2048
            if (ret > 0 && ret <= 2048) {
                buffer[ret] = 0; /* terminate the buffer */
            }
            else {
                send_error(socketfd, FORBIDDEN, "Request error, invalid size, < 0 or > 2048", buffer);
                sleep(5); // avoid spam
                break; // invalid request size, exit
            }
        }

        DEBUG_LOG("Full request:\n---------------------\nGET %s\n---------------------\n", buffer);
        { // keep only url
            int i;
            for (i = 0; i < BUFSIZE; i++) {
                if (buffer[i] == ' ') {
                    buffer[i] = 0;
                    break;
                }
            }
        }

        url_decode(*buffer == '/' ? &buffer[1] : buffer, buffer);

        { // check for illegal parent directory use ..
            int i = 0, n = strlen(buffer);
            for (i = 0; i < n - 1; i++) {
                if (buffer[i] == '.' && buffer[i + 1] == '.') {
                    send_error(socketfd, FORBIDDEN, "Parent directory (..) path names not supported", buffer);
                    continue; // keeplive
                }
            }
        }

        if (*buffer == 0)
            strcpy(buffer, ".");

        INFO_LOG("Requested, %s\n", buffer);

        struct stat s;
        long conent_len = 0;
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
                    continue; // keeplive
                }

                long conent_len = (long)lseek(file_fd, (off_t)0, SEEK_END); /* lseek to the file end to find the length */
                lseek(file_fd, (off_t)0, SEEK_SET); /* lseek back to the file start ready for reading */
                sprintf(buffer, "HTTP/1.1 200 OK\nServer: nweb\nContent-Length: %ld\n\n", conent_len);
                write_data(socketfd, buffer, strlen(buffer));

                /* send file in buffer size block - last block may be smaller */
                int nread;
                while ((nread = read(file_fd, buffer, BUFSIZE)) > 0) {
                    write_data(socketfd, buffer, nread);
                }
                close(file_fd);
                if (conent_len > BUFSIZE)
                    sleep(1); // wait a little after big file transfer
                continue; // keeplive
            }
        }
        else { /* file not found */
            send_error(socketfd, NOTFOUND, "Not Found", buffer);
            continue; // keeplive
        }
    }

    DEBUG_LOG("Child exiting...\n");
    shutdown(socketfd, SHUT_WR);
    close(socketfd);
    exit(0);
}

int main(int argc, char** argv)
{
    int i, pid, listenfd, socketfd;
    static struct sockaddr_in cli_addr; /* static = initialised to zeros */
    static struct sockaddr_in serv_addr; /* static = initialised to zeros */

    if (argc < 3 || argc > 4 || !strcmp(argv[1], "-?")) {
        PRINT_LOG("\thint: nweb Port-Number Top-Directory [trace level, silent(0)/info(1)/debug(2)]\n"
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
        PRINT_LOG("WARN: Can't root to directory %s\n", argv[2]);
        if (chdir(argv[2]) == -1) {
            PRINT_LOG("ERROR: Failed to change to directory %s\n", argv[2]);
            exit(4);
        }
    }

    if (argc == 4)
        APP_LOG_LEVEL = atoi(argv[3]);

    signal(SIGCHLD, SIG_IGN); /* let kernel automatically reap children */
    setpgrp(); /* break away from process group */
    /* setup the network socket */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        PRINT_LOG("ERROR: Failed to create socket\n");
        exit(6);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1]));
    if (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        PRINT_LOG("ERROR: Failed to bind socket to port, %s\n", argv[1]);
        exit(6);
    }

    if (listen(listenfd, 64) < 0) {
        PRINT_LOG("ERROR: Failed to listen to port, %s\n", argv[1]);
        exit(7);
    }

    INFO_LOG("nweb started at port %s\n", argv[1]);

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
                INFO_LOG("Serving client, %s:%d\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
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
RUN gcc -static -o /nwebs nweb.c
RUN echo 'cp /nwebs /webroot/nwebs' >> /run.sh
RUN echo '/nwebs 3140 /webroot' >> /run.sh
RUN chmod +x /run.sh
CMD /run.sh

Executed below commands-------------
docker build -t nwebs:1
docker run -v /root:/webroot nwebs:1 &
nwebs is copied /root, downloaded on browser
*/
