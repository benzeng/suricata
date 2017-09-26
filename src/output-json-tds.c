/* Copyright (C) 2015 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * TODO: Update \author in this file and in output-json-tds.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer TDS.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-tds.h"
#include "output-json-tds.h"

#ifdef HAVE_LIBJANSSON

typedef struct LogTDSFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogTDSFileCtx;

typedef struct LogTDSLogThread_ {
    LogTDSFileCtx *tdslog_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogTDSLogThread;


/*
    Note: Returned pointer should be freed.
*/
static uint8_t* FetchPrintableString( const uint8_t *pHexBuffer, uint32_t nBufferLen, char space )
{
    char bFlag = 0;
    uint32_t i = 0, j=0;
    uint8_t *pOutput = SCCalloc( 1, nBufferLen );
    
    memset( pOutput, 0, nBufferLen );
    for( i=0; i<nBufferLen; ++i ) {
        if( pHexBuffer[i] < 0x20  || pHexBuffer[i] >= 0x7F ) {
            if( !bFlag ) {
                pOutput[j++] = space;
                bFlag = 1;
            }
            // else skip !
        }
        else {
            bFlag = 0;
            pOutput[j++] = pHexBuffer[i];
        } 
    }

    pOutput[j++] = 0;
    return (pOutput);
}

static int JsonTDSLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    TdsTransaction *tdstx = tx;
    LogTDSLogThread *thread = thread_data;
    json_t *js, *tdsjs;

    SCLogNotice("Logging tds transaction %"PRIu64".", tdstx->tx_id);
    
    js = CreateJSONHeader((Packet *)p, 0, "tds");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    tdsjs = json_object();
    if (unlikely(tdsjs == NULL)) {
        goto error;
    }

    /* Convert the request buffer to a string then log. */
    char *log_buffer = (char *)FetchPrintableString( tdstx->full_packet_buffer, tdstx->full_packet_len, '|' );
    if (log_buffer != NULL) {
        if( tdstx->direction & STREAM_TOSERVER )
            json_object_set_new(tdsjs, "request", json_string(log_buffer));
        else
            json_object_set_new(tdsjs, "response", json_string(log_buffer));
        SCFree(log_buffer);
    }

    /* Convert the response buffer to a string then log. */
    /*
    char *response_buffer = BytesToString(tdstx->response_buffer,
        tdstx->response_buffer_len);
    if (response_buffer != NULL) {
        json_object_set_new(tdsjs, "response",
            json_string(response_buffer));
        SCFree(response_buffer);
    }
    */

    json_object_set_new(js, "tds", tdsjs);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->tdslog_ctx->file_ctx, &thread->buffer);

    json_decref(js);
    return TM_ECODE_OK;
    
error:
    json_decref(js);
    return TM_ECODE_FAILED;
}

static void OutputTDSLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogTDSFileCtx *tdslog_ctx = (LogTDSFileCtx *)output_ctx->data;
    SCFree(tdslog_ctx);
    SCFree(output_ctx);
}

static OutputCtx *OutputTDSLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    LogTDSFileCtx *tdslog_ctx = SCCalloc(1, sizeof(*tdslog_ctx));
    if (unlikely(tdslog_ctx == NULL)) {
        return NULL;
    }
    tdslog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(tdslog_ctx);
        return NULL;
    }
    output_ctx->data = tdslog_ctx;
    output_ctx->DeInit = OutputTDSLogDeInitCtxSub;

    SCLogNotice("TDS log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TDS);

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonTDSLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogTDSLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogTDS.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->tdslog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonTDSLogThreadDeinit(ThreadVars *t, void *data)
{
    LogTDSLogThread *thread = (LogTDSLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonTDSLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TDS, "eve-log", "JsonTDSLog",
        "eve-log.tds", OutputTDSLogInitSub, ALPROTO_TDS,
        JsonTDSLogger, JsonTDSLogThreadInit,
        JsonTDSLogThreadDeinit, NULL);

    SCLogNotice("TDS JSON logger registered.");
}

#else /* No JSON support. */

void JsonTDSLogRegister(void)
{
}

#endif /* HAVE_LIBJANSSON */
