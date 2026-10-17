#ifndef COMMON_H
#define COMMON_H

/* =====================================================================
 * Simplified FTP-style server for a security course.
 *
 * It works as a normal little file server for normal-length input, but
 * it is built on purpose around unchecked strcpy() calls at three spots
 * (SEARCH filename, LOGIN username, RECEIVE filename) so those can be
 * turned into working overflows later. Run it only on a lab VM.
 * ===================================================================== */

/* --- platform compat: sockets --------------------------------------- */
#ifdef _WIN32
  #define _CRT_SECURE_NO_WARNINGS   /* strcpy() is used on purpose */
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #ifdef _MSC_VER
    #pragma comment(lib, "ws2_32.lib")  /* MinGW links -lws2_32 in build.sh */
  #endif

  typedef SOCKET sock_t;
  #define SOCK_INVALID(s)    ((s) == INVALID_SOCKET)
  #define CLOSESOCK(s)       closesocket(s)
  #define SOCK_RECV(s,b,n)   recv((s), (b), (int)(n), 0)
  #define SOCK_SEND(s,b,n)   send((s), (b), (int)(n), 0)
#else
  #include <unistd.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>

  typedef int sock_t;
  #ifndef INVALID_SOCKET
    #define INVALID_SOCKET   (-1)
  #endif
  #define SOCK_INVALID(s)    ((s) < 0)
  #define CLOSESOCK(s)       close(s)
  #define SOCK_RECV(s,b,n)   read((s), (b), (n))
  #define SOCK_SEND(s,b,n)   write((s), (b), (n))
#endif

/* in compat.c */
int  net_init(void);        /* WSAStartup on Windows, no-op on Linux */
void net_cleanup(void);     /* WSACleanup on Windows, no-op on Linux */
void net_perror(const char *msg);

/* --- protocol / sizing --- */
#define PORT        2121
#define MAX_LINE    8192        /* max command line; big enough to overflow */
#define FTP_ROOT    "ftproot"   /* directory the server serves files from   */
#define MAX_USERS   32
#define MAX_NAME    256

/* per-connection state */
typedef struct {
    int  logged_in;
    char user[MAX_NAME];
} session_t;

#endif /* COMMON_H */
