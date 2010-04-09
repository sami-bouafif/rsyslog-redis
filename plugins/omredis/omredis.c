/* omtemplate.c
 * This is a template for an output module. It implements a very
 * simple single-threaded output, just as thought of by the output
 * plugin interface.
 *
 * NOTE: read comments in module-template.h for more specifics!
 *
 * File begun on 2009-03-16 by RGerhards
 *
 * Copyright 2009 Rainer Gerhards and Adiscon GmbH.
 *
 * This file is part of rsyslog.
 *
 * Rsyslog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Rsyslog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Rsyslog.  If not, see <http://www.gnu.org/licenses/>.
 *
 * A copy of the GPL can be found in the file "COPYING" in this distribution.
 */
#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include "dirty.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "cfsysline.h"
#include "conf.h"
#include "credis.h"

MODULE_TYPE_OUTPUT

/* internal structures
 */
DEF_OMOD_STATIC_DATA
DEFobjCurrIf(errmsg)

typedef struct _instanceData {
	REDIS	r_handle;		/* Redis handle */
	char*	r_server;		/* IP or hostname of Redis server */
	char*	r_password;		/* Redis password if it require authentification */
	uint	r_serverPort;	/*Redis server port */
	int		r_lastError;	/* Last error, 0 if all is ok */
} instanceData;

static char*	r_server	= NULL;
static char*	r_password	= NULL;
static uint		r_serverPort= 0;

BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
	/* RepeatedMsgReduction ("last message repeated n times") supported. */
	if(eFeat == sFEATURERepeatedMsgReduction)
		iRet = RS_RET_OK;
ENDisCompatibleWithFeature

/* Close and clean Redis connexion*/
static void closeRedis(instanceData *pData)
{
	ASSERT(pData != NULL);

	if(pData->r_handle != NULL)
	{
		credis_close(pData->r_handle);
		pData->r_handle = NULL;
	}
	if (pData->r_server != NULL)
		free(r_server);
	if (pData->r_password != NULL)
		free(r_password);
	
}


BEGINfreeInstance
CODESTARTfreeInstance
	/* cleanup block */
	 closeRedis(pData);
ENDfreeInstance


BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
	/* TODO: print some info (rdis server info for example) */
ENDdbgPrintInstInfo

/* translate numerical errors 
 * TODO: very ugly!!!! (Think about something else for messages)
 * Todo: NB. it's not my fault, credis does not report errors nicely
 * TODO: and im in hurry
 */
static void reportError(instanceData *pData)
{
	char* errMsg;

	ASSERT(pData != NULL);

	/* output log message */
	errMsg = NULL;
	if(pData->r_handle == NULL)
	{
		errmsg.LogError(0, NO_ERRCODE, "unknown DB error occured - could not obtain Redis handle");
	}
	else
	{ 
		switch(pData->r_lastError)
		{
			case CREDIS_ERR : 
					asprintf(&errMsg, "db error (%d): %s\n", pData->r_lastError, "CREDIS_ERR");
					break;
			case CREDIS_ERR_NOMEM:
					asprintf(&errMsg, "db error (%d): %s\n", pData->r_lastError, "CREDIS_ERR_NOMEM");
					break;
			case CREDIS_ERR_RESOLVE:
					asprintf(&errMsg, "db error (%d): %s\n", pData->r_lastError, "CREDIS_ERR_RESOLVE");
					break;
			case CREDIS_ERR_CONNECT:
					asprintf(&errMsg, "db error (%d): %s\n", pData->r_lastError, "CREDIS_ERR_CONNECT");
					break;
			case CREDIS_ERR_SEND:
					asprintf(&errMsg,  "db error (%d): %s\n", pData->r_lastError, "CREDIS_ERR_SEND");
					break;
			case CREDIS_ERR_RECV:
					asprintf(&errMsg,  "db error (%d): %s\n", pData->r_lastError, "CREDIS_ERR_RECV");
					break;
			case CREDIS_ERR_TIMEOUT:
					asprintf(&errMsg,  "db error (%d): %s\n", pData->r_lastError, "CREDIS_ERR_TIMEOUT");
					break;
			case CREDIS_ERR_PROTOCOL:
					asprintf(&errMsg,  "db error (%d): %s\n", pData->r_lastError, "CREDIS_ERR_PROTOCOL");
					break;
		}
		if (pData->r_lastError < 0)
			errmsg.LogError(0, NO_ERRCODE, "%s", errMsg);
		if (errMsg != NULL)
			free(errMsg);
	}
		
	return;
}

/* init redis connexion */
static rsRetVal initRedis(instanceData *pData)
{
	DEFiRet;

	ASSERT(pData != NULL);
	ASSERT(pData->r_handle == NULL);
	pData->r_handle = credis_connect(pData->r_server, pData->r_serverPort, 10000);
	if(pData->r_handle == NULL)
	{
		errmsg.LogError(0, RS_RET_SUSPENDED, "can not initialize Redis handle");
		iRet = RS_RET_SUSPENDED;
	}
	if (pData->r_password)
		if (credis_auth(pData->r_handle, pData->r_password) < 0)
		{
			errmsg.LogError(0, RS_RET_SUSPENDED, "invalid password");
			iRet = RS_RET_SUSPENDED;
		}
	RETiRet;
}

/* send message to redis
 * we use current time as key
 */
rsRetVal writeRedis(uchar *message, instanceData *pData)
{
	DEFiRet;
	int rc;
	
	ASSERT(message != NULL);
	ASSERT(pData != NULL);

	/* see if we are ready to proceed */
	if(pData->r_handle == NULL)
	{
		CHKiRet(initRedis(pData));
	}
	/* insert message */
	rc = credis_execcommand(pData->r_handle, (char*)message);
	pData->r_lastError = rc;
	if (rc < 0)
	{
		/* on error try one more time to insert */
		closeRedis(pData);
		CHKiRet(initRedis(pData));
		rc = credis_execcommand(pData->r_handle, (char*)message);
		if (rc < 0)
		{
			/* tried two time to insert message and failed */
			pData->r_lastError = rc;
			reportError(pData);	/* report error */
			closeRedis(pData);
			ABORT_FINALIZE(RS_RET_SUSPENDED); /* suspend the mod */
		}
	}
	
finalize_it:
	if(iRet == RS_RET_OK) {
		pData->r_lastError = 0; /* reset error */
	}

	RETiRet;
}


BEGINtryResume
CODESTARTtryResume
	if(pData->r_handle == NULL)
		iRet = initRedis(pData);
ENDtryResume

BEGINdoAction
CODESTARTdoAction
	/* For more tweaking we can retrieve message as an array of fields
	 * TODO: Discuss about it
	 */
	iRet = writeRedis(ppString[0], pData);
ENDdoAction


BEGINparseSelectorAct
CODESTARTparseSelectorAct
CODE_STD_STRING_REQUESTparseSelectorAct(1)
	/* is the config line is for us	 */
	if(strncmp((char*) p, ":omredis:", sizeof(":omredis:") - 1)) {
		ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
	}

	/* ok, if we reach this point, we have something for us */
	p += sizeof(":omredis:") - 1; /* eat indicator sequence  (-1 because of '\0'!) */
	CHKiRet(createInstance(&pData));

	/* check if a non-standard template is to be applied */
	if(*(p-1) == ';')
		--p;
	/* if we have, call rsyslog runtime to get us template. Note that StdFmt below is
	 * the standard name. Currently, we may need to patch tools/syslogd.c if we need
	 * to add a new standard template.
	 */
	CHKiRet(cflineParseTemplateName(&p, *ppOMSR, 0, OMSR_NO_RQD_TPL_OPTS, (uchar*) " StdFmt"));
	
	/* if we reach this point, all went well, and we can copy over to instanceData
	 * those configuration elements that we need.
	 */
	 if (r_server != NULL)
		CHKmalloc(pData->r_server = strdup(r_server));
	if (r_password != NULL)
		CHKmalloc(pData->r_password = strdup(r_password));
	pData->r_serverPort = (unsigned) r_serverPort;

CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct


BEGINmodExit
CODESTARTmodExit
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
ENDqueryEtryPt


/* Reset config variables for this module to default values.
 */
static rsRetVal
resetConfigVariables(uchar __attribute__((unused)) *pp, void __attribute__((unused)) *pVal)
{
	DEFiRet;
	if (r_server != NULL)
		free(r_server);
	if (r_password != NULL)
		free(r_password);
	r_server =r_password = NULL;
	r_serverPort = 0; 
	
	RETiRet;
}


BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
	CHKiRet(objUse(errmsg, CORE_COMPONENT));
	/* register our config handlers */
	/* confguration parameters MUST always be specified in lower case! */
	/* Parameters are:
	 * - ActionOmredisServerPort
	 * - ActionOmredisServerAddress
	 * - ActionOmredisServerPassword
	 */
	CHKiRet(omsdRegCFSLineHdlr((uchar *)"actionomredisserverport", 0, eCmdHdlrInt, NULL, &r_serverPort, STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr((uchar *)"actionomredisserveraddress", 0, eCmdHdlrGetWord, NULL, &r_server, STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr((uchar *)"actionomredisserverpassword", 0, eCmdHdlrGetWord, NULL, &r_password, STD_LOADABLE_MODULE_ID));
	/* "resetconfigvariables" should be provided. Notat that it is a chained directive */
	CHKiRet(omsdRegCFSLineHdlr((uchar *)"resetconfigvariables", 1, eCmdHdlrCustomHandler, resetConfigVariables, NULL, STD_LOADABLE_MODULE_ID));
ENDmodInit

/* vi:set ai:
 */
