/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __AGENTD_H
#define __AGENTD_H

#include "shared.h"
#include "sec.h"
#include "config/config.h"
#include "config/client-config.h"

/* Buffer functions */
#define full(i, j) ((i + 1) % (agt->buflength + 1) == j)
#define warn(i, j) ((float)((i - j + agt->buflength + 1) % (agt->buflength + 1)) / (float)agt->buflength >= ((float)warn_level/100.0))
#define nowarn(i, j) ((float)((i - j + agt->buflength + 1) % (agt->buflength + 1)) / (float)agt->buflength <= ((float)warn_level/100.0))
#define normal(i, j) ((float)((i - j + agt->buflength + 1) % (agt->buflength + 1)) / (float)agt->buflength <= ((float)normal_level/100.0))
#define capacity(i, j) (float)((i - j + agt->buflength + 1) % (agt->buflength + 1)) / (float)agt->buflength
#define empty(i, j) (i == j)
#define forward(x) x = (x + 1) % (agt->buflength + 1)

/* Buffer statuses */
#define NORMAL 0
#define WARNING 1
#define FULL 2
#define FLOOD 3

/* Client configuration */
int ClientConf(const char *cfgfile);

/* Agentd init function */
void AgentdStart(const char *dir, int uid, int gid, const char *user, const char *group) __attribute__((noreturn));

/* Event Forwarder */
void *EventForward(void);

/* Receiver messages */
int receive_msg(void);

/* Receiver messages for Windows */
void *receiver_thread(void *none);

/* Send integrity checking information about a file to the server */
int intcheck_file(const char *file_name, const char *dir);

/* Initialize agent buffer */
void buffer_init();

/* Send message to a buffer with the aim to avoid flooding issues */
int buffer_append(const char *msg);

/* Thread to dispatch messages from the buffer */
void *dispatch_buffer(void * arg);

/* Send message to server */
int send_msg(int agentid, const char *msg);

/* Extract the shared files */
char *getsharedfiles(void);

/* Initialize handshake to server */
void start_agent(int is_startup);

/* Connect to the server */
int connect_server(int initial_id);

/* Notify server */
void run_notify(void);

/* Format labels from config into string. Return 0 on success or -1 on error. */
int format_labels(char *str, size_t size);

// Thread to rotate internal log
void * w_rotate_log_thread(void * arg);

/*** Global variables ***/

/* Global variables. Only modified during startup. */

extern time_t available_server;
extern int run_foreground;
extern keystore keys;
extern agent *agt;

#endif /* __AGENTD_H */
