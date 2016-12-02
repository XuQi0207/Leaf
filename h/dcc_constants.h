#ifndef _DCC_CONSTANTS_H
#define	_DCC_CONSTANTS_H 
/* some macros */

#ifdef CHECKI
#undef CHECKI
#endif
#define CHECKI                  5       /* max interval to check for work to be done */

#ifdef MAXRETRY 
#undef MAXRETRY
#endif
#define MAXRETRY                5

#ifdef RETRYI
#undef RETRYI
#endif
#define RETRYI                  20

#define BFTLOGBUFSZ                1024
#define BFTPRTBUFSZ                180
#define BFTREPBUFSZ                5120    /* must be >= ipath + 4 * longsize */
#define BFTREQBUFSZ                1200    /* must be >= ipath + 4 * longsize */
#define BFTLISTBUFSZ               4096    /* must be > double size of struct dcc_request_entry */
#endif
