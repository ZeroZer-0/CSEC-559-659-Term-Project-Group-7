#ifndef PARSER_H
#define PARSER_H

typedef enum {
    CMD_LOGIN,      /* LOGIN user pass        - SEH overflow on username   */
    CMD_CREATE,     /* CREATE user pass                                    */
    CMD_SEARCH,     /* SEARCH "name"          - simple overflow on name    */
    CMD_LIST,       /* LIST                                                */
    CMD_PUT,        /* PUT "name" size        - upload; DEP/ROP on name    */
    CMD_GET,        /* GET "name"             - download from server       */
    CMD_HELP,
    CMD_VULN,       /* VULN                   - show intentional vulns      */
    CMD_EXIT,
    CMD_UNKNOWN
} cmd_type_t;

/* Splits a command line into argv-style tokens in place (NUL-terminating
 * inside `line`). Whitespace-separated; a token may be wrapped in
 * "double quotes" to allow spaces. argv[0] is the keyword.
 * Returns argc. argv entries point into `line`. */
int tokenize(char *line, char **argv, int max_argv);

/* Maps argv[0] (case-insensitive) to a command type. */
cmd_type_t command_of(const char *keyword);

#endif /* PARSER_H */
