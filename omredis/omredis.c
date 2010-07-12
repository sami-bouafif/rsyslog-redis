/* omredis.c
 * This is an implementation of a builtin output module for Redis server.
 *
 * NOTE: read comments in module-template.h in rsyslog source for more specifics!
 *
 * This file is licensed under the terms of the GPL version 3 or, at
 * your choice, any later version.
 *
 * Author: Sami Bouafif
 * <sami.bouafif@gmail.com>
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
#include "redis.h"

MODULE_TYPE_OUTPUT

/* internal structures
 */
DEF_OMOD_STATIC_DATA
DEFobjCurrIf(errmsg)

typedef struct _instanceData
{
  REDIS*  redisHandle;     /* Redis handle */
  char*   redisServer;     /* IP or hostname of Redis server */
  char*   redisPassword;   /* Redis password if it require authentification */
  char*   redisServerPort; /*Redis server port */
  char*   redisLastError;  /* Last error, 0 if all is ok */
} instanceData;

static char*  redisServer      = NULL;
static char*  redisServerPort = NULL;
static char*  redisPassword   = NULL;

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

  if(pData->redisHandle != NULL)
  {
    redis_close(pData->redisHandle);
    pData->redisHandle = NULL;
  }
  if (pData->redisServer != NULL)
    free(pData->redisServer);
  if (pData->redisPassword != NULL)
    free(pData->redisPassword);
  if (pData->redisServerPort != NULL)
    free(pData->redisServerPort);
  if (pData->redisLastError != NULL)
    free(pData->redisLastError);
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

/* Report error */
static void reportError(instanceData *pData)
{
  char* errMsg;

  ASSERT(pData != NULL);

  /* output log message */
  errMsg = NULL;
  if(pData->redisHandle == NULL)
  {
    errmsg.LogError(0, NO_ERRCODE, "Unknown DB error occured - could not obtain Redis handle");
  }
  else if (pData->redisLastError != NULL)
    errmsg.LogError(0, NO_ERRCODE, "Redis error : %s", pData->redisLastError);
  return;
}

/* init redis connexion */
static rsRetVal initRedis(instanceData *pData)
{
  DEFiRet;

  ASSERT(pData != NULL);
  ASSERT(pData->r_handle == NULL);
  pData->redisHandle = redis_connect(pData->redisServer, pData->redisServerPort);
  if(pData->redisHandle == NULL)
  {
    errmsg.LogError(0, RS_RET_SUSPENDED, "Can not initialize Redis handle");
    iRet = RS_RET_SUSPENDED;
  }
  /* TODO: Add authentification to redis server if needed */
  RETiRet;
}

/* send message to redis */
rsRetVal writeRedis(uchar *message, instanceData *pData)
{
  DEFiRet;
  RedisRetVal *rv;
  ASSERT(message != NULL);
  ASSERT(pData != NULL);

  /* see if we are ready to proceed */
  if(pData->redisHandle == NULL)
  {
    CHKiRet(initRedis(pData));
  }
  /* insert message */
  rv = redis_execStr(pData->redisHandle, REDIS_PROTOCOL_MULTIBULK, (char*)message, -1);
  if (rv == NULL)
  {
    /* on error try one more time to insert */
    closeRedis(pData);
    CHKiRet(initRedis(pData));
    rv = redis_execStr(pData->redisHandle, REDIS_PROTOCOL_MULTIBULK, (char*)message, -1);
    if (rv == NULL)
    {
      /* tried two time to insert message and failed */
      if (pData->redisLastError != NULL) free(pData->redisLastError);
      pData->redisLastError = strdup(redisError_getStr(redis_errCode));
      reportError(pData);  /* report error */
      closeRedis(pData);
      ABORT_FINALIZE(RS_RET_SUSPENDED); /* suspend the mod */
    }
  }

  if (redisRetVal_getType(rv) == REDIS_RETURN_ERROR)
  {
    if (pData->redisLastError != NULL) free(pData->redisLastError);
    errmsg.LogError(0, NO_ERRCODE, "%s : %s", "Redis Command", (char*)message);
    pData->redisLastError = strdup((char *)redisRetVal_getError(rv));
    reportError(pData);  /* report error */
    redisRetVal_free(rv);
    closeRedis(pData);
    ABORT_FINALIZE(RS_RET_SUSPENDED); /* suspend the mod */
  }
finalize_it:
  if(iRet == RS_RET_OK)
  {
    /* Reset last error */
    redisRetVal_free(rv);
    if (pData->redisLastError != NULL) free(pData->redisLastError);
    pData->redisLastError = NULL;
  }

  RETiRet;
}


BEGINtryResume
CODESTARTtryResume
  if(pData->redisHandle == NULL)
    iRet = initRedis(pData);
ENDtryResume

BEGINdoAction
CODESTARTdoAction
  /* For more tweaking we can retrieve message as an array of fields */
  iRet = writeRedis(ppString[0], pData);
ENDdoAction


BEGINparseSelectorAct
CODESTARTparseSelectorAct
CODE_STD_STRING_REQUESTparseSelectorAct(1)
  /* is the config line is for us   */
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
   if (redisServer != NULL)
    CHKmalloc(pData->redisServer = strdup(redisServer));
  if (redisPassword != NULL)
    CHKmalloc(pData->redisPassword = strdup(redisPassword));
  if (redisServerPort != NULL)
    CHKmalloc(pData->redisServerPort = strdup(redisServerPort));

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
  if (redisServer != NULL)
    free(redisServer);
  if (redisPassword != NULL)
    free(redisPassword);
  if (redisServerPort != NULL)
    free(redisServerPort);
  redisServer = redisPassword = redisServerPort = NULL;

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
   * - OmredisServerPort
   * - OmredisServerAddress
   * - OmredisServerPassword
   */
  CHKiRet(omsdRegCFSLineHdlr((uchar *)"omredisserverport", 0, eCmdHdlrGetWord, NULL, &redisServerPort, STD_LOADABLE_MODULE_ID));
  CHKiRet(omsdRegCFSLineHdlr((uchar *)"omredisserveraddress", 0, eCmdHdlrGetWord, NULL, &redisServer, STD_LOADABLE_MODULE_ID));
  CHKiRet(omsdRegCFSLineHdlr((uchar *)"omredisserverpassword", 0, eCmdHdlrGetWord, NULL, &redisPassword, STD_LOADABLE_MODULE_ID));
  /* "resetconfigvariables" should be provided. Notat that it is a chained directive */
  CHKiRet(omsdRegCFSLineHdlr((uchar *)"resetconfigvariables", 1, eCmdHdlrCustomHandler, resetConfigVariables, NULL, STD_LOADABLE_MODULE_ID));
ENDmodInit

/* vi:set ai:
 */
