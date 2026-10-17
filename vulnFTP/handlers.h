#ifndef HANDLERS_H
#define HANDLERS_H

#include "common.h"

/* argv/argc are the tokenized command (argv[0] is the keyword).
 * Each returns normally; file ops require a logged-in session. */

void handle_login(session_t *s, sock_t fd, char **argv, int argc);
void handle_create(session_t *s, sock_t fd, char **argv, int argc);
void handle_search(session_t *s, sock_t fd, char **argv, int argc);
void handle_list(session_t *s, sock_t fd);
void handle_put(session_t *s, sock_t fd, char **argv, int argc);   /* upload   */
void handle_get(session_t *s, sock_t fd, char **argv, int argc);   /* download */

/* HELP / VULN - no login required. Each streams a text file to the client
 * as plain lines ending with a "." line (help.txt / vuln.txt). */
void handle_help(sock_t fd);
void handle_vuln(sock_t fd);

#endif /* HANDLERS_H */
