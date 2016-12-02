#
#  Copyright (C) 1999 by CERN/IT/PDP/DM
#  All rights reserved
#
#       @(#)oralink.mk,v 1.1 2000/01/22 10:14:26 CERN IT-PDP/DM Jean-Philippe Baud
 
#    Link nsdaemon with Oracle libraries.

include $(ORACLE_HOME)/precomp/lib/env_precomp.mk
PROLDLIBS=$(LLIBCLNTSH) $(LLIBCLIENT) $(LLIBSQL) $(STATICTTLIBS)

nsdaemon: $(NSDAEMON_OBJS)
	$(CC) -o nsdaemon $(CLDFLAGS) $(NSDAEMON_OBJS) $(LIBS) -L$(LIBHOME) $(PROLDLIBS)
