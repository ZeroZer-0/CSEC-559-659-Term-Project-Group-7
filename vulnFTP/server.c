//Simplified FTP-style server

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "common.h"
#include "parser.h"
#include "handlers.h"

#ifdef _WIN32
  #include <windows.h>
  #include <direct.h>
#else
  #include <pthread.h>
  #include <signal.h>
  #include <sys/types.h>
#endif


static void make_root(void)
{
#ifdef _WIN32
    _mkdir(FTP_ROOT);
#else
    mkdir(FTP_ROOT, 0755);
#endif
}

#ifdef _WIN32
static void print_vuln_addresses(void)
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE ntd = GetModuleHandleA("ntdll.dll");
    FARPROC va = k32 ? GetProcAddress(k32, "VirtualAlloc")   : NULL;
    FARPROC vp = k32 ? GetProcAddress(k32, "VirtualProtect") : NULL;
    FARPROC rm = ntd ? GetProcAddress(ntd, "RtlMoveMemory")  : NULL;
    printf("Vuln Addresses: VirtualAlloc=%p  VirtualProtect=%p  RtlMoveMemory=%p\n",
           (void *)va, (void *)vp, (void *)rm);
    fflush(stdout);
}
#endif

static int read_line(sock_t fd, char *buf, int bufsize)
{
    int total = 0;
    while (total < bufsize - 1) {
        char c;
        int n = SOCK_RECV(fd, &c, 1);
        if (n <= 0) return (total > 0) ? total : -1;
        if (c == '\n') break;
        if (c != '\r') buf[total++] = c;
    }
    buf[total] = '\0';
    return total;
}

static void serve_client(sock_t client)
{
    session_t s;
    memset(&s, 0, sizeof(s));

    char line[MAX_LINE];
    const char *banner =
        "Welcome. Commands: LOGIN CREATE SEARCH LIST PUT GET HELP VULN EXIT\n";
    SOCK_SEND(client, banner, strlen(banner));

    for (;;) {
        int n = read_line(client, line, sizeof(line));
        if (n < 0) break;
        if (n == 0) continue;

        char *argv[8];
        int argc = tokenize(line, argv, 8);
        if (argc == 0) continue;

        switch (command_of(argv[0])) {
            case CMD_LOGIN:   handle_login(&s, client, argv, argc);   break;
            case CMD_CREATE:  handle_create(&s, client, argv, argc);  break;
            case CMD_SEARCH:  handle_search(&s, client, argv, argc);  break;
            case CMD_LIST:    handle_list(&s, client);                break;
            case CMD_PUT:     handle_put(&s, client, argv, argc);     break;
            case CMD_GET:     handle_get(&s, client, argv, argc);     break;
            case CMD_HELP:    handle_help(client);                   break;
            case CMD_VULN:    handle_vuln(client);                   break;
            case CMD_EXIT: {
                const char *bye = "GOODBYE\n";
                SOCK_SEND(client, bye, strlen(bye));
                CLOSESOCK(client);
                return;
            }
            default: {
                const char *unk = "ERR unknown command\n";
                SOCK_SEND(client, unk, strlen(unk));
                break;
            }
        }
    }

    CLOSESOCK(client);
}


#ifdef _WIN32
static DWORD WINAPI client_thread(LPVOID p) { serve_client((sock_t)p); return 0; }
#else
static void *client_thread(void *p) { serve_client((sock_t)(long)p); return NULL; }
#endif

static void spawn_client(sock_t client)
{
#ifdef _WIN32
    CreateThread(NULL, 0, client_thread, (LPVOID)client, 0, NULL);
#else
    pthread_t t;
    pthread_create(&t, NULL, client_thread, (void *)(long)client);
    pthread_detach(t);
#endif
}

int main(int argc, char **argv)
{
    int port = PORT;
    if (argc > 1) port = atoi(argv[1]);

    if (net_init() != 0) return 1;
    make_root();

#ifdef _WIN32
    LoadLibraryA("essfunc.dll");
    print_vuln_addresses();
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    sock_t listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (SOCK_INVALID(listen_fd)) { net_perror("socket"); net_cleanup(); return 1; }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((unsigned short)port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        net_perror("bind"); net_cleanup(); return 1;
    }
    if (listen(listen_fd, SOMAXCONN) != 0) {
        net_perror("listen"); net_cleanup(); return 1;
    }

    printf("lab ftp server listening on port %d (root: %s/)\n", port, FTP_ROOT);
    fflush(stdout);

    for (;;) {
        struct sockaddr_in ca;
        socklen_t calen = sizeof(ca);
        sock_t client = accept(listen_fd, (struct sockaddr *)&ca, &calen);
        if (SOCK_INVALID(client)) { net_perror("accept"); continue; }
        printf("connection from %s:%d\n", inet_ntoa(ca.sin_addr), ntohs(ca.sin_port));
        fflush(stdout);
        spawn_client(client);
    }
}
