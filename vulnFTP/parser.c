#include <ctype.h>
#include <string.h>
#if defined(_MSC_VER)
  #define strcasecmp _stricmp
#else
  #include <strings.h>
#endif
#include "parser.h"

int tokenize(char *line, char **argv, int max_argv)
{
    int argc = 0;
    char *p = line;

    while (*p && argc < max_argv) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        if (*p == '"') {
            p++;
            argv[argc++] = p;
            while (*p && *p != '"') p++;
            if (*p == '"') { *p = '\0'; p++; }
        } else {
            argv[argc++] = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            if (*p) { *p = '\0'; p++; }
        }
    }
    return argc;
}

cmd_type_t command_of(const char *keyword)
{
    if (strcasecmp(keyword, "LOGIN")   == 0) return CMD_LOGIN;
    if (strcasecmp(keyword, "CREATE")  == 0) return CMD_CREATE;
    if (strcasecmp(keyword, "SEARCH")  == 0) return CMD_SEARCH;
    if (strcasecmp(keyword, "LIST")    == 0) return CMD_LIST;
    if (strcasecmp(keyword, "PUT")     == 0) return CMD_PUT;
    if (strcasecmp(keyword, "GET")     == 0) return CMD_GET;
    if (strcasecmp(keyword, "HELP")    == 0) return CMD_HELP;
    if (strcasecmp(keyword, "VULN")    == 0) return CMD_VULN;
    if (strcasecmp(keyword, "EXIT")    == 0) return CMD_EXIT;
    if (strcasecmp(keyword, "QUIT")    == 0) return CMD_EXIT;
    return CMD_UNKNOWN;
}
