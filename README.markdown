rsyslog-redis
=============

Redis output module for rsyslog.
This plugin allows rsyslog to write syslog messages to Redis server.

#Installing rsyslog-redis
Tested with rsyslog-5.4.0.

1. Apply the patch 'rsyslog-redis.patch' to the source of rsyslog:

		cd path/to/rsyslog-5.4.0
		patch -p1 -i rsyslog-redis.patch
			
2. Copy omredis directory to plugins directory of rsyslog source.
3. Regenerate autotools related files:

		cd path/to/rsyslog-5.4.0
		autoreconf	

4. Add `--enable-redis` to `./configure` switches.
5. make && make install

NB. libredis must be installed to build rsyslog-redis. Check [libredis](http://github.com/sami-bouafif/libredis) on github.

#Configuration
##Selector line
To use rsyslog-redis, a selector line of this form can be used in rsyslog.conf:

	:omredis:;TemplateName

TemplateName must be a valid Redis command. It is advised to use the 'sql' format string option in Template to ensure a proper quoting of "'" characters.   
The following is an example of template string that can be used with rsyslog-redis:

	$template redis,"ZADD messages %syslogtag% '%timegenerated% %HOSTNAME% %syslogtag%%msg:::drop-last-lf%'", sql
	
Note that "'" characters are used to delimit arguments (to Redis command) containing Whitespaces. Without these quotes, each token is interpreted as an arg to the command.

##Config handlers
Three parameters can be specified to rsyslog-redis via syslog $... directives, namely:

- `$OmredisServerAddress`: address of Redis server. If not specified, localhost is used.
- `$OmredisServerPort`: port thar Redis server listen to. If not specified, default port is used (6379).
- `$OmredisServerPassword`: password used for authentification with Redis server. It is not yet implemented.
 