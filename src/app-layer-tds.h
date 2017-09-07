/* Copyright (C) 2017 Ben
 *
 */

 /**
 * \defgroup tdslayer 12306 TDS layer support
 *
 * @{
 */

/**
 * \file
 *
 * \author Ben <zengxd@s-ec.com>
 *
 * This file provides a 12306 TDS protocol support for the engine.
 */
#ifndef __APP_LAYER_TDS_H__
#define __APP_LAYER_TDS_H__
 
#include "util-radix-tree.h"
#include "util-file.h"
#include "detect-engine-state.h"
#include "util-streaming-buffer.h"
#include "queue.h"


void RegisterTdsParsers(void);
void TdsParserRegisterTests(void);

typedef struct TDSCfgDir_ {
    StreamingBufferConfig sbcfg;
} TDSCfgDir;

typedef struct TdsQueryAndResult_ {

    char* queryBuffer;
    char* ResultBuffer;
};

typedef struct TdsConnection_ {

/* Members */
    /* TDS Connection Info */
    uint32_t SrcIp;
    uint32_t SrcPort;
    uint32_t DestIp;
    uint32_t DestPort;

    /* TDS Query and Result, Keey Max 50 Query/Result */

    
}TdsConnection;

typedef struct TdsConnectionParser_ {

/* Members */
    TdsConnection *tdsConnection;

/* Methods */

}TdsConnectionParser;



typedef struct TDSTransaction_ {

    TdsConnectionParser TdsParser;


    uint64_t tx_id;             /*<< Internal transaction ID. */

    AppLayerDecoderEvents *decoder_events; /*<< Application layer
                                            * events that occurred
                                            * while parsing this
                                            * transaction. */

    uint8_t *request_buffer;
    uint32_t request_buffer_len;

    /* flags indicating which loggers that have logged */
    uint32_t logged;

    uint8_t *response_buffer;
    uint32_t response_buffer_len;

    uint8_t response_done; /*<< Flag to be set when the response is
                            * seen. */

    DetectEngineState *de_state;

    TAILQ_ENTRY(TDSTransaction_) next;

} TDSTransaction;

typedef struct TDSState_ {

    TAILQ_HEAD(, TDSTransaction_) tx_list; /**< List of TDS transactions
                                       * associated with this
                                       * state. */

    uint64_t transaction_max; /**< A count of the number of
                               * transactions created.  The
                               * transaction ID for each transaction
                               * is allocted by incrementing this
                               * value. */

    uint16_t events; /**< Number of application layer events created
                      * for this state. */

} TDSState;

#endif


