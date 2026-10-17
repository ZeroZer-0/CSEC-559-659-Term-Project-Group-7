#include <stdio.h>
#include "common.h"

int net_init(void)
{
#ifdef _WIN32
    WSADATA wsa;
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (rc != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", rc);
        return -1;
    }
#endif
    return 0;
}

void net_cleanup(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

void net_perror(const char *msg)
{
#ifdef _WIN32
    fprintf(stderr, "%s: WSA error %d\n", msg, WSAGetLastError());
#else
    perror(msg);
#endif
}
