#define _GNU_SOURCE

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

#define NULL_CHAR '\0'

#define HTTP_SUCCESS 200
#define HTTP_PARTIAL_CONTENT 206
#define HTTP_NOT_MODIFIED 304
#define HTTP_FORBIDDEN 403
#define HTTP_NOTFOUND 404

#define BUFSIZE 1024 * 256
#define KEEP_ALIVE 1
#define RECEIVE_TIMEOUT_SEC 10

#define ERROR_LEVEL -2
#define WARN_LEVEL -1
#define PRINT_LEVEL 0
#define INFO_LEVEL 1
#define DEBUG_LEVEL 2
#define TRACE_LEVEL 3

#define _PRINT_LOG_(log_level, str_format, ...)                                       \
    if (APP_LOG_LEVEL >= log_level) {                                                 \
        time_t curtime = time(NULL);                                                  \
        struct tm ltm;                                                                \
        localtime_r(&curtime, &ltm);                                                  \
        printf("%d-%02d-%02d %02d:%02d:%02d [%6d] [%5s] " str_format,                 \
            ltm.tm_year + 1900, ltm.tm_mon + 1, ltm.tm_mday,                          \
            ltm.tm_hour, ltm.tm_min, ltm.tm_sec, getpid(), LOG_LEVELS[log_level + 2], \
            ##__VA_ARGS__);                                                           \
    \
}

#define ERROR_LOG(str_format, ...) _PRINT_LOG_(ERROR_LEVEL, str_format, ##__VA_ARGS__)
#define WARN_LOG(str_format, ...) _PRINT_LOG_(WARN_LEVEL, str_format, ##__VA_ARGS__)
#define PRINT_LOG(str_format, ...) _PRINT_LOG_(PRINT_LEVEL, str_format, ##__VA_ARGS__)
#define INFO_LOG(str_format, ...) _PRINT_LOG_(INFO_LEVEL, str_format, ##__VA_ARGS__)
#define DEBUG_LOG(str_format, ...) _PRINT_LOG_(DEBUG_LEVEL, str_format, ##__VA_ARGS__)
#define TRACE_LOG(str_format, ...) _PRINT_LOG_(TRACE_LEVEL, str_format, ##__VA_ARGS__)

char* LOG_LEVELS[6] = { "ERROR", "WARN", "INFO", "PRINT", "DEBUG", "TRACE" };
int APP_LOG_LEVEL = INFO_LEVEL;
int request_count = 0;
char FAVICON[275] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0xF3, 0xFF, 0x61, 0x00, 0x00, 0x00, 0xDA, 0x49, 0x44, 0x41, 0x54, 0x38, 0x4F, 0x63, 0x5C, 0x75, 0xF7, 0xFF, 0x7F, 0x06, 0x0A, 0x00, 0xE3, 0x30, 0x34, 0xE0, 0xC6, 0xE9, 0xC3, 0x0C, 0x1F, 0xDE, 0xBC, 0x64, 0xD0, 0xB1, 0x74, 0x62, 0x78, 0x78, 0xE3, 0x22, 0xC3, 0xD3, 0xBB, 0x37, 0x19, 0x94, 0x74, 0x8C, 0x18, 0x54, 0xF4, 0xCD, 0xB0, 0x86, 0x14, 0x46, 0x18, 0x6C, 0x5B, 0x30, 0x91, 0x61, 0xED, 0x94, 0x16, 0x06, 0x05, 0x4D, 0x7D, 0x06, 0x76, 0x4E, 0x6E, 0x06, 0x5E, 0x41, 0x61, 0x86, 0x63, 0x5B, 0x56, 0x32, 0xA4, 0xB5, 0xCE, 0x64, 0xB0, 0x0D, 0x88, 0xC1, 0x30, 0x04, 0x6B, 0x20, 0x96, 0xFB, 0x19, 0x31, 0x18, 0x3A, 0x78, 0x31, 0x44, 0x14, 0xB5, 0x80, 0x35, 0x6C, 0x9C, 0xD5, 0xC5, 0x70, 0x7E, 0xFF, 0x36, 0x86, 0x86, 0xE5, 0x07, 0x88, 0x37, 0xC0, 0x3F, 0xBD, 0x82, 0xC1, 0xCA, 0x3B, 0x0C, 0xAC, 0xE1, 0xE4, 0xCE, 0x75, 0x0C, 0xEB, 0xA6, 0xB6, 0x30, 0x74, 0x6E, 0x3A, 0x37, 0x14, 0x0C, 0x38, 0xB2, 0x69, 0x19, 0xC3, 0xE2, 0xF6, 0x12, 0x06, 0x4D, 0x53, 0x3B, 0x86, 0xD8, 0xCA, 0x6E, 0x06, 0x61, 0x49, 0x59, 0xB0, 0x17, 0xE6, 0x35, 0xE4, 0x30, 0xC4, 0x94, 0x77, 0x61, 0x04, 0x24, 0x46, 0x20, 0x9E, 0xDA, 0xB9, 0x9E, 0xE1, 0xF5, 0xB3, 0x87, 0x60, 0xBF, 0x5A, 0x7A, 0x85, 0x31, 0x08, 0x89, 0x4B, 0x31, 0x7C, 0x7C, 0xFB, 0x8A, 0xE1, 0xE8, 0xE6, 0xE5, 0x0C, 0xC2, 0x12, 0x32, 0x0C, 0xE6, 0x1E, 0xC1, 0x28, 0xE1, 0x30, 0x1C, 0x93, 0x32, 0xA9, 0x39, 0x1B, 0x00, 0x81, 0x59, 0x89, 0x61, 0x19, 0xD2, 0x2F, 0x72, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82 };

char* toUpper(char* s)
{
    char* p;
    for (p = s; *p != NULL_CHAR; p++)
        *p = (char)toupper(*p);

    return s;
}

void trim(char* str)
{
    int i = 0, j = strlen(str);
    while (j > 0 && isspace(str[j - 1]))
        str[--j] = NULL_CHAR;
    while (isspace(str[i]))
        i++;
    if (i > 0)
        memmove(str, str + i, j - i + 1);
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

void write_data(int socketfd, char* data, int length, int log_level)
{
    if (data[length] != NULL_CHAR /* check is needed to skp static strings */)
        data[length] = NULL_CHAR; // this is needed for log to write data out
    _PRINT_LOG_(log_level, "Writing data %d bytes: \n---------------------\n%s\n---------------------\n", length, data);
    write(socketfd, data, length);
}

void exit_web(int socketfd, int exit_code)
{
    shutdown(socketfd, SHUT_WR);
    close(socketfd);
    INFO_LOG("Fork exit code %d, served %d requests\n", exit_code, request_count);
    exit(exit_code);
}

void send_error(int socketfd, int http_ret_code, char* http_msg, int sleep_sec, int exit_code, char* bigbuffer)
{
    INFO_LOG("Error return, %d, %s\n", http_ret_code, http_msg);
    int len = sprintf(bigbuffer, "HTTP/1.1 %d\nContent-Length: %d\nContent-Type: text/html\n\n%s", http_ret_code, strlen(http_msg), http_msg);
    write_data(socketfd, bigbuffer, len, DEBUG_LEVEL);
    if (sleep_sec > 0)
        sleep(sleep_sec);
    if (exit_code != 0)
        exit_web(socketfd, exit_code);
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
    int filename_content_size = 0;

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
    int len = 350 + 22 + 105 * nfiles + filename_content_size;
    len = sprintf(buffer, "HTTP/1.1 200 OK\nContent-Length: %d\nContent-Type: text/html\nCache-control: private\n\n", len);
    write_data(socketfd, buffer, len, DEBUG_LEVEL);

    int bigbuffer_pos = 0;
    char str_fsize[16];

    void bufferOrWrite(int socketfd, char* buffer, int buffer_len, char* bigbuffer, int* bigbuffer_pos)
    {
        if (buffer == NULL || *bigbuffer_pos + buffer_len >= BUFSIZE) {
            write_data(socketfd, bigbuffer, *bigbuffer_pos, TRACE_LEVEL);
            *bigbuffer_pos = 0;
        }
        if (buffer != NULL) {
            sprintf(&bigbuffer[*bigbuffer_pos], "%s", buffer);
            *bigbuffer_pos += buffer_len;
        }
    }

    // 350 chars
    len = sprintf(buffer, "<html><head><style>a:link { text-decoration: none; color: blue;} a:visited { text-decoration: none; color: blue;} a:hover { text-decoration: none; color: brown; } td { padding: 0 10; } body { font-family: consolas; } tr:hover {background-color:#e5e5e5;}</style><script>function f(a){window.location.href=a.text;}</script></head><body><table border=0>");
    bufferOrWrite(socketfd, buffer, len, bigbuffer, &bigbuffer_pos);

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
        len = sprintf(buffer, "<tr><td>%d-%02d-%02d %02d:%02d:%02d</td><td>%16s</td><td><a href=\"#\" onclick=\"f(this)\">%s</a></td></tr>",
            ltm->tm_year + 1900, ltm->tm_mon + 1, ltm->tm_mday, ltm->tm_hour, ltm->tm_min, ltm->tm_sec,
            str_fsize, arr_files[i]->name);

        bufferOrWrite(socketfd, buffer, len, bigbuffer, &bigbuffer_pos);
    }
    // 22 chars
    len = sprintf(buffer, "</table></body></html>");
    bufferOrWrite(socketfd, buffer, len, bigbuffer, &bigbuffer_pos);
    bufferOrWrite(socketfd, NULL, 0, bigbuffer, &bigbuffer_pos); // nothing else to buffer write

    for (i = 0; i < nfiles; i++) {
        free(arr_files[i]); // free memory
    }

    closedir(dp);
}

/* this is a child web server process, so we can exit on errors */
void web(int socketfd)
{
    { // set read time, support for only GET, no need for extensive receive time
        struct timeval tv = { RECEIVE_TIMEOUT_SEC, RECEIVE_TIMEOUT_SEC * 1000 };
        if (setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            WARN_LOG("Error setting socket receive timeout");
        }
    }

    char buffer[BUFSIZE + 1];
    char buff_str9k[9000];

    for (; KEEP_ALIVE; request_count++) {

        char http_method[16];
        { // handle http method
            int nread = read(socketfd, http_method, 4); // read 1st 4 chars
            if (nread < 1) {
                break; // nothing read, exit
            }
            http_method[4] = NULL_CHAR;

            if (strncmp(toUpper(http_method), "GET ", 4)) {
                sprintf(buff_str9k, "Only GET is supported, requested %s", http_method);
                send_error(socketfd, HTTP_FORBIDDEN, buff_str9k, 5, 101, buffer);
            }
        }

        char hdr_if_modified_since[32]; // format Wed, 21 Oct 2015 07:28:00 GMT
        int hdr_range[2] = { -1, -1 };
        { // handle header
            int nread = read(socketfd, buffer, 9000); // read max get request size 8192
            if (nread < 0 || nread > 8192) {
                send_error(socketfd, HTTP_FORBIDDEN, "Request error, invalid size, < 0 or > 8192", 5, 102, buffer);
            }
            buffer[nread] = NULL_CHAR; /* terminate the buffer */

            // read If-Modified-Since header
            hdr_if_modified_since[0] = NULL_CHAR;
            char* hdr_found;

            { // if-modified-since
                hdr_found = strcasestr(buffer, "if-modified-since:");
                if (hdr_found > 0) {
                    sscanf(&hdr_found[18] /* skipping If-Modified-Since: */, "%[^\n]s", hdr_if_modified_since);
                    trim((char*)hdr_if_modified_since);
                }
            }

            { // range
                hdr_found = strcasestr(buffer, "range:");
                if (hdr_found > 0) {
                    hdr_found = strcasestr(&hdr_found[6], "bytes=");
                    if (hdr_found > 0) {
                        hdr_range[0] = atoll(&hdr_found[6]);
                        hdr_found = strstr(&hdr_found[6 + 1], "-");
                        if (hdr_found > 0) {
                            trim(&hdr_found[1]);
                            if (strlen(&hdr_found[1]) > 0)
                                hdr_range[1] = atoll(&hdr_found[1]);
                        }
                    }
                }
            }
            DEBUG_LOG("Headers, if-modified-since(%s), range(%d-%d)\n", hdr_if_modified_since, hdr_range[0], hdr_range[1]);
        }

        DEBUG_LOG("Full request:\n---------------------\n%s%s\n---------------------\n", http_method, buffer);
        { // teminate headers to keep just url
            char* space_found = strchr(buffer, ' ');
            if (!space_found) {
                sprintf(buff_str9k, "Url demarker space char not found");
                send_error(socketfd, HTTP_FORBIDDEN, buff_str9k, 5, 103, buffer);
            }
            *space_found = NULL_CHAR;
        }

        int param_refresh_flag = 0;
        int param_tail_flag = 0;
        { // handle params
            char* found_params = strstr(buffer, "?");
            if (found_params) {
                param_refresh_flag = strstr(found_params, "refresh") ? 1 : 0;
                param_tail_flag = strstr(found_params, "tail") ? 1 : 0;
                *found_params = NULL_CHAR; // terminate params, to keep just resource name
            }
            DEBUG_LOG("Flags, refresh(%d), tail(%d)\n", param_refresh_flag, param_tail_flag);
        }

        url_decode(*buffer == '/' ? &buffer[1] : buffer, buffer);
        if (strstr(buffer, "..")) { // check for illegal parent directory use ..
            send_error(socketfd, HTTP_FORBIDDEN, "Parent directory (..) path names not supported", 5, 104, buffer);
        }

        if (*buffer == 0)
            strcpy(buffer, ".");

        INFO_LOG("%s%s\n", http_method, buffer);

        struct stat request_file_stat;
        if (stat(buffer, &request_file_stat) == 0) { /* file found */

            struct tm* request_file_gmt = gmtime(&request_file_stat.st_mtim.tv_sec);
            char last_modified[32];
            strftime(last_modified, 32, "%a, %d %b %Y %H:%M:%S GMT", request_file_gmt);

            if (request_file_stat.st_mode & S_IFDIR) { /* directory */
                listdir(buffer, socketfd, buffer);
                continue;
            }
            else if (!param_refresh_flag && strcmp(last_modified, hdr_if_modified_since) == 0) {
                write_data(socketfd, "HTTP/1.1 304\n\n", 14, DEBUG_LEVEL); // client cache is good, send 304
                continue;
            }
            else { /* file */
                int file_fd = open(buffer, O_RDONLY | O_NONBLOCK);
                if (file_fd < 0) {
                    send_error(socketfd, HTTP_NOTFOUND, "Not Found", 0, 0, buffer);
                    continue;
                }

                // WARNING!!! using signed int every where. sizes greater than max signed int val will fail
                // 4 byte int range is -2,147,483,648 to 2,147,483,647. so, this is good until 2G size
                // for lseek returns off_t which is a signed int
                // for greater than 2G content, try long with compilation flag -D_FILE_OFFSET_BITS=64
                int content_len = lseek(file_fd, 0, SEEK_END); /* lseek to the file end to find the length */
                lseek(file_fd, 0, SEEK_SET); /* lseek to the file start */

                int http_ret_code = HTTP_SUCCESS;
                *buff_str9k = NULL_CHAR;
                if (hdr_range[0] > -1) {
                    if (hdr_range[1] == -1)
                        hdr_range[1] = content_len > hdr_range[0] + BUFSIZE ? hdr_range[0] + BUFSIZE : content_len;
                    lseek(file_fd, hdr_range[0], SEEK_SET);
                    sprintf(buff_str9k, "Content-Range: bytes %d-%d/%d\n", hdr_range[0], hdr_range[1], content_len);
                    content_len = hdr_range[1] - hdr_range[0];
                    http_ret_code = HTTP_PARTIAL_CONTENT;
                } // ignore tail flag if range is on
                else if (content_len > BUFSIZE && param_tail_flag) {
                    lseek(file_fd, -BUFSIZE, SEEK_END);
                    content_len = BUFSIZE; /* lseek to the last BUFSIZE */
                }
                int len = sprintf(buffer, "HTTP/1.1 %d \nServer: nweb\nAccept-Ranges: bytes\nContent-Length: %d\n%sCache-control: private\nLast-Modified: %s\n\n",
                    http_ret_code, content_len, buff_str9k /*range*/, last_modified);
                write_data(socketfd, buffer, len, DEBUG_LEVEL);

                /* send file in buffer size block, last block may be smaller */
                int nwritten = 0;
                while ((len = read(file_fd, buffer, BUFSIZE)) > 0) {
                    // in case the file is being continuosly appended with new text, size changes fast
                    // do not write more than committed content-length to client
                    // even if there is more data to be read, break. client must execute a fetch again
                    // if file size is cut short before the read, less bytes will be rendered
                    // for ranges as well, do not serve data over the range
                    // for tail, if file size is cut short more than BUFSIZE, gibberish or fork may die
                    write_data(socketfd, buffer, nwritten + len > content_len ? content_len - nwritten : len, TRACE_LEVEL);
                    nwritten += len;
                    if (nwritten >= content_len || param_tail_flag)
                        break;
                }
                close(file_fd);
                if (content_len >= BUFSIZE)
                    sleep(1); // wait a little after big file transfer

                // if file size is cut short before the read, less bytes will be rendered
                if (nwritten < content_len)
                    break; // close connection to indicate completion to client

                continue;
            }
        }
        else if (strstr(buffer, "favicon.")) { // favicon.ico request
            if (*hdr_if_modified_since) { // never resend icon
                write_data(socketfd, "HTTP/1.1 304\n\n", 14, DEBUG_LEVEL);
            }
            else { // send stock icon
                write_data(socketfd, "HTTP/1.1 200 \nServer: nweb\nContent-Length: 275\nCache-control: private\n"
                                     "Last-Modified: Sat, 13 Aug 2005 22:20:00 GMT\n\n" /*some date*/,
                    116, DEBUG_LEVEL);
                write_data(socketfd, FAVICON, 275, DEBUG_LEVEL);
            }
            continue;
        }
        else { /* file not found */
            send_error(socketfd, HTTP_NOTFOUND, "Not Found", 0, 0, buffer);
            continue;
        }
    }

    exit_web(socketfd, 100);
}

int main(int argc, char** argv)
{
    int n, pid, listenfd, socketfd;
    static struct sockaddr_in cli_addr; /* static = initialised to zeros */
    static struct sockaddr_in serv_addr; /* static = initialised to zeros */

    setenv("TZ", "IST-5:30", 1);
    tzset();

    if (argc < 3 || argc > 4 || !strcmp(argv[1], "-?")) {
        ERROR_LOG("\thint: nweb Port-Number Top-Directory [trace level, silent(0)/info(1)/debug(2)/trace(3)]\n"
                  "\tnweb is a small and very safe mini web server\n"
                  "\tserves only from the named directory or its sub-directories\n"
                  "\tThere is no fancy features = safe and secure\n\n"
                  "\tExample: nweb 8181 /home/nwebdir\n\n");

        ERROR_LOG("\tNot Supported: directories / /etc /bin /lib /tmp /usr /dev /sbin \n"
                  "\tNo warranty given or implied, Nigel Griffiths nag@uk.ibm.com\n"
                  "\tDirectory listing, url decoding, logging updates by janardhan.chinta@capgemini.com\n");
        exit(0);
    }

    if (!strncmp(argv[2], "/", 2) || !strncmp(argv[2], "/etc", 5) || !strncmp(argv[2], "/bin", 5) || !strncmp(argv[2], "/lib", 5) || !strncmp(argv[2], "/tmp", 5) || !strncmp(argv[2], "/usr", 5) || !strncmp(argv[2], "/dev", 5) || !strncmp(argv[2], "/sbin", 6)) {
        ERROR_LOG("ERROR: Bad top directory %s, see nweb -?\n", argv[2]);
        exit(1);
    }

    if ((n = chdir(argv[2]) != 0)) {
        ERROR_LOG("ERROR: Failed to change to directory %s, errno %d\n", argv[2], n);
        exit(2);
    }

    if ((n = chroot(argv[2])) != 0) {
        WARN_LOG("Can't root to directory %s, errno %d\n", argv[2], n);
    }

    if (argc == 4)
        APP_LOG_LEVEL = atoi(argv[3]);

    signal(SIGCHLD, SIG_IGN); /* let kernel automatically reap children */
    setpgrp(); /* break away from process group */
    /* setup the network socket */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        ERROR_LOG("ERROR: Failed to create socket\n");
        exit(3);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1]));
    if (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        ERROR_LOG("ERROR: Failed to bind socket to port, %s\n", argv[1]);
        exit(4);
    }

    if (listen(listenfd, 64) < 0) {
        ERROR_LOG("ERROR: Failed to listen to port, %s\n", argv[1]);
        exit(5);
    }

    INFO_LOG("nweb started at port %s\n", argv[1]);

    while (1) {
        socklen_t length = sizeof(cli_addr);

        if ((socketfd = accept(listenfd, (struct sockaddr*)&cli_addr, &length)) < 0) {
            ERROR_LOG("Accept error\n");
        }

        if ((pid = fork()) < 0) {
            ERROR_LOG("Fork error\n");
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
RUN echo 'gcc -static /webroot/nweb.c -o /webroot/nwebs' >> run.sh
RUN echo 'sleep 2' >> /run.sh
RUN chmod +x /run.sh
CMD /run.sh

Executed below commands-------------
docker build -t nwebs:1
docker run -v /root:/webroot nwebs:1 &
/root/nwebs is built, download
*/
