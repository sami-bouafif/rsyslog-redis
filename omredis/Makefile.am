pkglib_LTLIBRARIES = omredis.la

omredis_la_SOURCES = omredis.c
omredis_la_CPPFLAGS =  $(RSRT_CFLAGS) $(LIBREDIS_CFLAGS) $(PTHREADS_CFLAGS) 
omredis_la_LDFLAGS = -module -avoid-version
omredis_la_LIBADD = $(LIBREDIS_LIBS)

EXTRA_DIST = 
