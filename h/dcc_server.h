/*
 * Copyright (C) 2008-2010 by IHEP/CC
 * All rights reserved
 * dcc_server.h v0.1 2008-07-06 16:47:34
 * Written by Yaodong Cheng, Computing Center, IHEP
 * Contact: Yaodong.cheng@ihep.ac.cn
 */
#ifndef _DCC_SERVER_H
#define _DCC_SERVER_H
#ifdef USE_MYSQL
#include <mysql.h>
#endif
#include "stage_limits.h"
#include "dcc.h"

#define VERINFO "DCC %s server: Version %s.%s, PID=%d\n"
#define CA_MAXGUIDLEN	36   /* maximum length for a guid */
#define PERDREAD		60	 /* The period of read one file */
#define NBPREAD			10   /* Number of read in PERDREAD time interval */
#define FSRANDOM		1	 /* random algorithm ID for fs selection */
#define FSINCREMENT		2	 /* random algorithm ID for fs selection */
#define FSMAXSPACE		3	 /* random algorithm ID for fs selection */
#define HASHLEN			1013 /* The length of hash table */

/*
 * Various circular list operations.
 */
#define CLIST_ITERATE_BEGIN(X,Y) {if ( (X) != NULL ) {(Y)=(X); do {
#define CLIST_ITERATE_END(X,Y) Y=(Y)->next; } while ((X) != (Y));}}
#define CLIST_INSERT(X,Y) {if ((X) == NULL) {X=(Y); (X)->next = (X)->prev = (X);} \
else {(Y)->next=(X); (Y)->prev=(X)->prev; (Y)->next->prev=(Y); (Y)->prev->next=(Y);}}
#define CLIST_DELETE(X,Y) {if ((Y) != NULL) {if ( (Y) == (X) ) (X)=(X)->next; \
 if ((Y)->prev != (Y) && (Y)->next != (Y)) {\
 (Y)->prev->next = (Y)->next; (Y)->next->prev = (Y)->prev;} else {(X)=NULL;}}}

#define CLIST_DELSUB(X, Y) { \
		CLIST_ITERATE_BEGIN((X), (Y)) { \
			if ((X) != (Y)) {CLIST_DELETE((X), (Y));free((Y));(Y)= (X);} \
		}CLIST_ITERATE_END((X), (Y));free((X));}

#define RETURN(x) \
        {\
        if (thip->dbfd.tr_started) \
                if (x) \
                        (void) dcc_abort_tr (&thip->dbfd); \
                else \
                        (void) dcc_end_tr (&thip->dbfd); \
        return ((x)); \
        }

struct dcc_dbfd {
	int idx; /* index in array of Cns_dbfd */
#ifdef USE_ORACLE
#ifdef USE_OCI
	Lda_Def lda; /* logon data area */
	ub1 hda[HDA_SIZE]; /* host data area */
#endif
#else
#ifdef USE_MYSQL
	MYSQL mysql;
#endif
#endif
	int tr_started;
};

#ifdef USE_MYSQL
typedef char dcc_dbrec_addr[21];
typedef MYSQL_RES *DCCDBLISTPTR;
#endif

struct dcc_srv_thread_info {
	int s; /* socket for communication with client, or request index in reqlist */
	int db_open_done;
	struct dcc_dbfd dbfd;
	char errbuf[1024];
};

typedef struct raw_list {
	u_signed64 reqid;
	struct xfile_list *xfiles; //file list in this request
	struct vol_list *vols; //volume list in this request
	struct raw_list *prev;
	struct raw_list *next;
} raw_list_t;
typedef struct xfile_list {
	char filename[STAGE_MAX_HSMLENGTH + 1];
	char vid[CA_MAXVIDLEN + 1];
	int fseq;
	struct raw_list *raw; //Parent raw request
	struct xfile_list *prev;
	struct xfile_list *next;
} xfile_list_t;
typedef struct vol_list {
	char vid[CA_MAXVIDLEN + 1];
	char dgn[CA_MAXDGNLEN + 1];
	int status;
	struct raw_list *raw;
	struct vol_list *prev;
	struct vol_list *next;
} vol_list_t;
typedef struct tapefile_list {
	char filename[STAGE_MAX_HSMLENGTH + 1];
	int fseq;
	int status;
	struct task_list *task;
	struct tapefile_list *prev;
	struct tapefile_list *next;
} tapefile_list_t;
typedef struct task_list {
	char vid[CA_MAXVIDLEN + 1];
	int doing;
	struct tapefile_list *xfiles; //file list in this request
	struct task_list *prev;
	struct task_list *next;
} task_list_t;
typedef struct req_list {
	char vid[CA_MAXVIDLEN + 1];
	char dgn[CA_MAXDGNLEN + 1];
	int doing; /* 0: initial, 1: being, 2: finished */
} req_list_t;
typedef struct dgn_list {
	char dgn[CA_MAXDGNLEN+1];
	int nbfreedrive;
	struct dgn_list *next;
} dgn_list_t;

#define REQLISTLEN 18 /* The length of one requsest list in RR */
#endif
