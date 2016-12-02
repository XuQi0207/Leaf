/*
 * sysreq_constants.h,v 1.2 1999/12/09 13:46:26 jdurand Exp
 */

/*
 * Copyright (C) 1990-1999 by CERN/IT/PDP/DC
 * All rights reserved
 */
 
/*
 * @(#)sysreq_constants.h,v 1.2 1999/12/09 13:46:26 CERN IT-PDP/DC Frederic Hemmer
 */

/* config.h     SYSREQ network interface configuration                  */
 
#ifndef _CONFIG_H_INCLUDED_
#define  _CONFIG_H_INCLUDED_

#define SYSREQ_NAME "sysreq"    /* Name of SYSREQ (in /etc/services)    */
#define SYSREQ_PROTO "tcp"      /* Communication protocol               */
#define SYSREQ_PORT  4001       /* Well known port if not in services   */
#define SYSREQ_BACKLOG 5        /* Listen() backlog                     */
#define SYSREQ_RETRY_SEED  10   /* Seed for progressive sysreq retries  */
#define SYSREQ_RETRY_MAX   130  /* Total number of sysreq retries       */
#define SYSREQ_RETRY_DELAY 30   /* Delay (sec.) between sysreq retries  */
 
#define S_MAGIC 0x103090        /* Server magic number                  */
#define C_MAGIC 0x100360        /* Client magic number                  */
 
#define ACCEPT_RETRY_MAX   5    /* Number of accept() max retries       */
#define ACCEPT_RETRY_DELAY 5    /* Delay between accept() retries       */
 
#define SERVICESDB      1       /* Use /etc/services db if set          */

#endif /* _CONFIG_H_INCLUDED_ */
