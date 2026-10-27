#include "common.h"      /* must come first: pulls in winsock2.h on Windows */
#include "handlers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
  #include <windows.h>
#else
  #include <dirent.h>
#endif

/* ------------------------------------------------------------------ */
/* small helpers                                                      */
/* ------------------------------------------------------------------ */
static void reply(sock_t fd, const char *msg)
{
    SOCK_SEND(fd, msg, strlen(msg));
}

/* send exactly n bytes */
static int send_all(sock_t fd, const char *buf, long n)
{
    long off = 0;
    while (off < n) {
        int w = SOCK_SEND(fd, buf + off, n - off);
        if (w <= 0) return -1;
        off += w;
    }
    return 0;
}

/* read exactly n bytes */
static int recv_exact(sock_t fd, char *buf, long n)
{
    long off = 0;
    while (off < n) {
        int r = SOCK_RECV(fd, buf + off, n - off);
        if (r <= 0) return -1;
        off += r;
    }
    return 0;
}

/* build "ftproot/<name>" into out */
static void root_path(char *out, size_t outsz, const char *name)
{
    snprintf(out, outsz, "%s/%s", FTP_ROOT, name);
}

/* ------------------------------------------------------------------ */
/* in-memory account store, seeded with student/student               */
/* ------------------------------------------------------------------ */
typedef struct { char user[MAX_NAME]; char pass[MAX_NAME]; } account_t;
static account_t g_accts[MAX_USERS] = { { "student", "student" } };
static int g_acct_count = 1;

static int check_login(const char *user, const char *pass)
{
    for (int i = 0; i < g_acct_count; i++)
        if (strcmp(g_accts[i].user, user) == 0 &&
            strcmp(g_accts[i].pass, pass) == 0)
            return 1;
    return 0;
}

/* ================================================================== */
/* LOGIN user pass                                                    */
/*                                                                      */
/* VULN SPOT 2 (SEH target on Windows): the username is copied into a  */
/* fixed stack buffer with strcpy(). Normal usernames work; an         */
/* over-long username overflows. Wired to real auth so the server      */
/* actually logs you in.                                               */
/* ================================================================== */
void handle_login(session_t *s, sock_t fd, char **argv, int argc)
{
    if (argc < 3) { reply(fd, "ERR usage: LOGIN <user> <pass>\n"); return; }

    char username[2000];
    strcpy(username, argv[1]);          /* <-- VULNERABLE */

    if (check_login(username, argv[2])) {
        s->logged_in = 1;
        strncpy(s->user, username, sizeof(s->user) - 1);
        s->user[sizeof(s->user) - 1] = '\0';
        reply(fd, "OK logged in\n");
    } else {
        reply(fd, "ERR bad credentials\n");
    }
}

/* ================================================================== */
/* CREATE user pass   (benign, bounded)                               */
/* ================================================================== */
void handle_create(session_t *s, sock_t fd, char **argv, int argc)
{
    (void)s;
    if (argc < 3) { reply(fd, "ERR usage: CREATE <user> <pass>\n"); return; }
    if (g_acct_count >= MAX_USERS) { reply(fd, "ERR account table full\n"); return; }

    for (int i = 0; i < g_acct_count; i++)
        if (strcmp(g_accts[i].user, argv[1]) == 0) {
            reply(fd, "ERR account exists\n"); return;
        }

    account_t *a = &g_accts[g_acct_count++];
    strncpy(a->user, argv[1], MAX_NAME - 1); a->user[MAX_NAME - 1] = '\0';
    strncpy(a->pass, argv[2], MAX_NAME - 1); a->pass[MAX_NAME - 1] = '\0';
    reply(fd, "OK account created\n");
}

/* ================================================================== */
/* SEARCH "name"                                                      */
/*                                                                      */
/* VULN SPOT 1 (plain stack overflow, cross-platform): filename copied */
/* into a 128-byte stack buffer with strcpy(). Then actually stats the */
/* file under ftproot and reports its size.                           */
/* ================================================================== */
void handle_search(session_t *s, sock_t fd, char **argv, int argc)
{
    if (!s->logged_in) { reply(fd, "ERR not logged in\n"); return; }
    if (argc < 2) { reply(fd, "ERR usage: SEARCH <name>\n"); return; }

    char filename[128];
    strcpy(filename, argv[1]);          /* <-- VULNERABLE */

    char path[MAX_LINE];
    root_path(path, sizeof(path), filename);

    struct stat st;
    char out[MAX_NAME + 64];
    if (stat(path, &st) == 0) {
        snprintf(out, sizeof(out), "FOUND %s %ld bytes\n",
                 filename, (long)st.st_size);
    } else {
        snprintf(out, sizeof(out), "NOTFOUND %s\n", filename);
    }
    reply(fd, out);
}

/* ================================================================== */
/* LIST   - list files in ftproot                                     */
/* ================================================================== */
void handle_list(session_t *s, sock_t fd)
{
    if (!s->logged_in) { reply(fd, "ERR not logged in\n"); return; }

#ifdef _WIN32
    WIN32_FIND_DATAA fd_data;
    HANDLE h = FindFirstFileA(FTP_ROOT "\\*", &fd_data);
    if (h == INVALID_HANDLE_VALUE) { reply(fd, "(empty)\n"); return; }
    do {
        if (!(fd_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            char line[MAX_NAME + 2];
            snprintf(line, sizeof(line), "%s\n", fd_data.cFileName);
            reply(fd, line);
        }
    } while (FindNextFileA(h, &fd_data));
    FindClose(h);
#else
    DIR *d = opendir(FTP_ROOT);
    if (!d) { reply(fd, "(empty)\n"); return; }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char line[MAX_NAME + 2];
        snprintf(line, sizeof(line), "%s\n", e->d_name);
        reply(fd, line);
    }
    closedir(d);
#endif
    reply(fd, ".\n");   /* end-of-listing marker */
}

/* ================================================================== */
/* PUT "storename" size   - client uploads a file TO the server.      */
/* The client picks storename (the basename of its local file) and    */
/* sends the byte count; the server stores the bytes as ftproot/      */
/* <storename>.                                                       */
/* Protocol: server replies "READY\n", reads exactly <size> bytes,    */
/* writes ftproot/<storename>, then replies "OK stored\n".            */
/*                                                                      */
/* VULN SPOT 3 (advanced / DEP-bypass ROP target on Windows):          */
/* storename is copied into a 1000-byte stack buffer with strcpy().    */
/* ================================================================== */
void handle_put(session_t *s, sock_t fd, char **argv, int argc)
{
    if (!s->logged_in) { reply(fd, "ERR not logged in\n"); return; }
    if (argc < 3) { reply(fd, "ERR usage: PUT <storename> <size>\n"); return; }

    char filename[1000];
    strcpy(filename, argv[1]);          /* <-- VULNERABLE */

    long size = atol(argv[2]);
    if (size < 0 || size > 100L * 1024 * 1024) {
        reply(fd, "ERR bad size\n"); return;
    }

    char path[MAX_LINE];
    root_path(path, sizeof(path), filename);

    FILE *f = fopen(path, "wb");
    if (!f) { reply(fd, "ERR cannot create\n"); return; }

    reply(fd, "READY\n");

    char chunk[4096];
    long left = size;
    int ok = 1;
    while (left > 0) {
        long want = left < (long)sizeof(chunk) ? left : (long)sizeof(chunk);
        if (recv_exact(fd, chunk, want) != 0) { ok = 0; break; }
        fwrite(chunk, 1, want, f);
        left -= want;
    }
    fclose(f);

    reply(fd, ok ? "OK stored\n" : "ERR transfer failed\n");
}

/* ================================================================== */
/* HELP / VULN  - no credentials required. Both just stream a text     */
/* file to the client as plain lines, terminated by a line containing  */
/* only "." (the same end marker LIST uses). The client prints the     */
/* lines; nothing is saved to a file on the client side.               */
/*                                                                      */
/* HELP streams ./help.txt (how to use the service).                   */
/* VULN streams ./vuln.txt (which field is vulnerable to what).        */
/* If the file is missing, a default copy is written first.            */
/* ================================================================== */
static const char *DEFAULT_HELP =
    "Lab FTP server - command help\n"
    "\n"
    "LOGIN <user> <pass>       authenticate (default: student / student)\n"
    "CREATE <user> <pass>      create a new account\n"
    "SEARCH \"<name>\"           check if a file exists under the server root\n"
    "LIST                      list files in the server root\n"
    "PUT \"<name>\" <size>       upload a file to the server (stored as <name>)\n"
    "GET \"<name>\"              download a file from the server\n"
    "HELP                      show this help text (no login needed)\n"
    "VULN                      show the intentional vulnerabilities (no login)\n"
    "EXIT                      close the connection\n"
    "\n"
    "Notes:\n"
    "- LOGIN, CREATE, HELP and VULN need no login; everything else does.\n"
    "- Quote names that contain spaces.\n";

static const char *DEFAULT_VULN =
    "Lab FTP server - intentional vulnerabilities\n"
    "\n"
    "SEARCH \"<name>\"   simple stack buffer overflow on the file name\n"
    "                 (reachable on Windows and Linux)\n"
    "LOGIN \"<user>\"    Windows SEH-bypass overflow on the username\n"
    "PUT \"<name>\"      stack overflow on the stored name; DEP-bypass ROP\n"
    "                 target (Windows, advanced)\n"
    "\n"
    "These are deliberate, for the course exploit-development work.\n";

static void ensure_file(const char *path, const char *def)
{
    FILE *f = fopen(path, "rb");
    if (f) { fclose(f); return; }
    f = fopen(path, "wb");
    if (f) { fputs(def, f); fclose(f); }
}

/* stream a text file to the client, then a line containing only "." */
static void send_text_then_dot(sock_t fd, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { reply(fd, "ERR not available\n.\n"); return; }

    char chunk[4096];
    size_t r;
    int last = '\n';
    while ((r = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        if (send_all(fd, chunk, (long)r) != 0) { fclose(f); return; }
        last = (unsigned char)chunk[r - 1];
    }
    fclose(f);
    if (last != '\n') reply(fd, "\n");   /* ensure "." begins its own line */
    reply(fd, ".\n");
}

void handle_help(sock_t fd)
{
    ensure_file("help.txt", DEFAULT_HELP);
    send_text_then_dot(fd, "help.txt");
}

void handle_vuln(sock_t fd)
{
    ensure_file("vuln.txt", DEFAULT_VULN);
    send_text_then_dot(fd, "vuln.txt");
}

/* ================================================================== */
/* GET "name"   - server sends the file TO the client (download).     */
/* The client names a file under the server root; the client side     */
/* decides where to save it locally (GET's second arg is client-only).*/
/* Protocol: server replies "OK <size>\n" then <size> raw bytes,      */
/* or "ERR not found\n".                                              */
/* ================================================================== */
void handle_get(session_t *s, sock_t fd, char **argv, int argc)
{
    if (!s->logged_in) { reply(fd, "ERR not logged in\n"); return; }
    if (argc < 2) { reply(fd, "ERR usage: GET <name>\n"); return; }

    char path[MAX_LINE];
    root_path(path, sizeof(path), argv[1]);

    FILE *f = fopen(path, "rb");
    if (!f) { reply(fd, "ERR not found\n"); return; }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char hdr[64];
    snprintf(hdr, sizeof(hdr), "OK %ld\n", size);
    reply(fd, hdr);

    char chunk[4096];
    size_t r;
    while ((r = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        if (send_all(fd, chunk, (long)r) != 0) break;
    }
    fclose(f);
}
