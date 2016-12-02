/*
 * Copyright (C) 2008-2010 by IHEP/CC
 * All rights reserved
 * bft_api.h v0.1 2009-07-29 15:34:22
 * Written by Yaodong Cheng, Computing Center, IHEP
 * Contact: Yaodong.cheng@ihep.ac.cn
 */
#ifndef _BFT_API_H
#define _BFT_API_H
#include <sys/types.h>
#include "dcc.h"
#include "dcc_constants.h"

#define STAGE_MAX_HSMLENGTH 166 /* Limitation on hsm filename length */
#define BFT_MAXREQNUM 	16	/* max number of files in one request list */
#define BFT_REQ_START	1	/* begin to request */
#define BFT_REQ_END		2	/* stop this request */
struct bft_resrvlist {
	char fl[BFT_MAXREQNUM][STAGE_MAX_HSMLENGTH+1];
	int nbentries; /* the number of file in the list */
	int fd; /* socket to connect to BFT server */
};
typedef struct {
	int fd; /* socket for communication with server */
	int eol; /* end of list */
	int index; /* entry index in buffer */
	int nbentries; /* number of entries in buffer */
	char *buf; /* cache buffer for list entries */
} bft_request_list;

struct bft_request_entry {
	u_signed64 reqid;
	char xfile[STAGE_MAX_HSMLENGTH+1];
	uid_t uid;
	gid_t gid;
	char client[CA_MAXHOSTNAMELEN + 1];
	time_t rtime;
	int status;
};
/*Internal */
char *stat2str(int status);
int stat2int(char *status);

int bft_resrv(int flag, struct bft_resrvlist *rl, int noretry, u_signed64 *reqid);
struct bft_request_entry *bft_qry(int, bft_request_list *, u_signed64, const char *, int);
int cerrmsg(char *func, char *msg, ...);
int dcc_ping();
int dcc_pingx(const char *server, int port, int type, int verbose, int noretry);
int bft_del(u_signed64, char *);
int bft_delx(const char *,int,int, u_signed64, char *, int, int);
int bft_stagein(const char *, char *, int); 
#endif
