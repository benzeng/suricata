/* Copyright (C) 2017 Ben
 *
 */

/**
 * \ingroup tdslayer
 *
 * @{
 */

/**
 * \file
 *
 * \author Ben <zengxd@s-ec.com>
 *
 * This file provides a TDS protocol support for the engine.
 */

 #include "suricata-common.h"
 #include "stream.h"
 #include "conf.h"
 
 #include "util-unittest.h"
 
 #include "app-layer-detect-proto.h"
 #include "app-layer-parser.h"
 
 #include "app-layer-tds.h"
 
 /* The default port to probe for TDS traffic if not provided in the
  * configuration file. */
 #define TDS_DEFAULT_PORT "7100"
 
 /* The minimum size for an TDS message. For some protocols this might
  * be the size of a header. */
 #define TDS_MIN_FRAME_LEN 15
 
 /* Enum of app-layer events for an TDS protocol. Normally you might
  * have events for errors in parsing data, like unexpected data being
  * received. For TDS we'll make something up, and log an app-layer
  * level alert if an empty message is received.
  *
  * Example rule:
  *
  * alert tds any any -> any any (msg:"SURICATA TDS empty message"; \
  *    app-layer-event:tds.empty_message; sid:X; rev:Y;)
  */
 enum {
     TDS_DECODER_EVENT_EMPTY_MESSAGE,
 };
 
 SCEnumCharMap tds_decoder_event_table[] = {
     {"EMPTY_MESSAGE", TDS_DECODER_EVENT_EMPTY_MESSAGE},
 
     // event table must be NULL-terminated
     { NULL, -1 },
 };


 
 
 static int TdsStateGetEventInfo(const char *event_name, int *event_id,
     AppLayerEventType *event_type)
 {
     *event_id = SCMapEnumNameToValue(event_name, tds_decoder_event_table);
     if (*event_id == -1) {
         SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                    "template enum map table.",  event_name);
         /* This should be treated as fatal. */
         return -1;
     }
 
     *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;
 
     return 0;
 }
 
 static AppLayerDecoderEvents *TdsGetEvents(void *state, uint64_t tx_id)
 {
    TDSState *tds_state = state;
    struct TdsTransaction_ *tx;
 
     TAILQ_FOREACH(tx, &tds_state->tx_list, next) {
         if (tx->tx_id == tx_id) {
             return tx->decoder_events;
         }
     } 
     return NULL;
 }
 
 static int TdsHasEvents(void *state)
 {
    TDSState *tds_state = state;
    return tds_state->events;
 }
 
 /**
  * \brief Probe the input to see if it looks like TDS.
  *
  * \retval ALPROTO_TDS if it looks like TDS, otherwise
  *     ALPROTO_UNKNOWN.
  */
 static AppProto TdsProbingParser(uint8_t *input, uint32_t input_len,
     uint32_t *offset)
 {
     /* Very simple test - if there is input, this is TDS. */
     if (input_len >= TDS_MIN_FRAME_LEN) {
         SCLogNotice("Detected as ALPROTO_TDS.");
         return ALPROTO_TDS;
     }
 
     SCLogNotice("Protocol not detected as ALPROTO_TDS.");
     return ALPROTO_UNKNOWN;
 }


/* TDSState Private methods */
 
static void TdsTxPacketFree( void *pList )
{
   struct TdsFragmentPacketList *pPacketList = (struct TdsFragmentPacketList *)pList;

   TdsFragmentPacket *pFragment = NULL;

   while ((pFragment = (TdsFragmentPacket *)TAILQ_FIRST(pPacketList)) != NULL) {
       TAILQ_REMOVE(pPacketList, pFragment, next);
       SCFree( pFragment->pfragmentBuffer );
       SCFree(pFragment);
   }
}

static TdsTransaction *TdsTxAlloc(TDSState *tds, uint8_t direction )
{
    struct TdsTransaction_ *tx = SCCalloc(1, sizeof(TdsTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }
    memset( tx, 0, sizeof(TdsTransaction) );

    /* Increment the transaction ID on the state each time one is
     * allocated. */
    tx->tx_id = tds->transaction_max++;
    
    if( direction & STREAM_TOCLIENT ) {
        tds->reponse_curr = tx;
    }
    else {
        tds->request_curr = tx;
    }

    TAILQ_INIT(&tx->tdsPackets);
    TAILQ_INSERT_TAIL(&tds->tx_list, tx, next);
    return tx;
}

static void TdsTxFree(TDSState *tds, void *tx)
{
    TdsTransaction *tds_tx = tx;

    TdsTxPacketFree( &tds_tx->tdsPackets );
     
    AppLayerDecoderEventsFreeEvents( &tds_tx->decoder_events );
  
    if (tds_tx->de_state != NULL) {
        DetectEngineStateFree( tds_tx->de_state );
    }

    if( tds->request_curr == tds_tx )
        tds->request_curr = NULL;
    if( tds->reponse_curr == tds_tx )
        tds->reponse_curr = NULL;
    
    if( tds_tx->full_packet_buffer != NULL )
        SCFree( tds_tx->full_packet_buffer );

    SCFree(tds_tx);
}

 static void *TdsStateAlloc(void)
 {
     SCLogNotice("Allocating TDS state.");
     TDSState *state = SCCalloc(1, sizeof(TDSState));
     if (unlikely(state == NULL)) {
         return NULL;
     }
     memset( state, 0, sizeof( TDSState ) );

     state->sbcfg.flags = STREAMING_BUFFER_NOFLAGS;
     state->sbcfg.buf_slide = 2048;
     state->sbcfg.buf_size = 4096;

     state->sbRequest = StreamingBufferInit( &state->sbcfg );
     state->sbResponse = StreamingBufferInit( &state->sbcfg );

     TAILQ_INIT(&state->tx_list);
     return state;
 }
 
 static void TdsStateFree(void *state)
 {
     TDSState *tds_state = state;
     TdsTransaction *tx;
     SCLogNotice("Freeing TDS state.");

     while ((tx = TAILQ_FIRST(&tds_state->tx_list)) != NULL) {
        TAILQ_REMOVE(&tds_state->tx_list, tx, next);
        TdsTxFree(tds_state, tx);
     }

     StreamingBufferFree( tds_state->sbRequest );
     StreamingBufferFree( tds_state->sbResponse );
     
     SCFree(tds_state);
 }


 static void TdsStateTxFree(void *state, uint64_t tx_id)
 {
    TDSState *tds = state;
    TdsTransaction *tx = NULL, *ttx;

    TAILQ_FOREACH_SAFE(tx, &tds->tx_list, next, ttx) {
        if (tx->tx_id != tx_id) {
            continue;
        }

        TAILQ_REMOVE(&tds->tx_list, tx, next);
        TdsTxFree(tds, tx);
        break;
    }

    SCReturn;
 }

 static void TdsSetTxLogged(void *state, void *vtx, uint32_t logger)
 {
     TdsTransaction *tx = (TdsTransaction *)vtx;
     tx->logged |= logger;
 }

 static int TdsGetTxLogged(void *state, void *vtx, uint32_t logger)
 {
    TdsTransaction *tx = (TdsTransaction *)vtx;
    if (tx->logged & logger)
         return 1;
 
    return 0;
 }

 static int TdsGetAlstateProgressCompletionStatus(uint8_t direction) 
 {
    return 1;
 }

 static int TdsGetStateProgress(void *tx, uint8_t direction)
 {
    TdsTransaction *tds = (TdsTransaction *)tx;
    int retval = 0;

    if( tds->bComplete )
        retval = 1;

    SCReturnInt(retval);
 }

 static uint64_t TdsGetTxCnt(void *state)
 {
    SCEnter();
    uint64_t count = ((uint64_t)((TDSState *)state)->transaction_max);
    SCReturnUInt(count);
 }

 static void *TdsGetTx(void *state, uint64_t tx_id)
 {
    TDSState *tds = state;
    struct TdsTransaction_ *tx = NULL;

    if (tds->request_curr && tds->request_curr->tx_id == (tx_id)) {
        SCReturnPtr(tds->request_curr, "void");
    }
    if (tds->reponse_curr && tds->reponse_curr->tx_id == (tx_id)) {
        SCReturnPtr(tds->reponse_curr, "void");
    }

    TAILQ_FOREACH(tx, &tds->tx_list, next) {
        if (tx_id != tx->tx_id) {
            continue;
        }
        SCReturnPtr(tx, "void");
    }

    SCReturnPtr(NULL, "void");
 }


 static DetectEngineState *TdsGetTxDetectState(void *vtx)
 {
    TdsTransaction *tx = vtx;
    return tx->de_state;
 }


 static int TdsSetTxDetectState(void *state, void *vtx,
     DetectEngineState *s)
 {
    TdsTransaction *tx = vtx;
    tx->de_state = s;
    return 0;
 }

 
 /* Try to Match TDS header: 0F 00 | 0F 01 , data_len >= 8 */   
 static int FindTdsHead( const uint8_t *data, uint32_t data_len )
 {
    uint32_t i = 0;

    if( data_len < 15 )
         return -1;
    
    while( (i+1) < data_len ) {
        if( ( data[i] != 0x0F ) || ( data[i+1] != 0x01 && data[i+1] != 0x00 ) ) {
            i++;
            continue;
        }               
        if( data[i+8] != 0x21 && data[i+8] != 0x61 && data[i+8] != 0 ) {
            i++;
            continue;
        }
        uint16_t nTdsPacketLen = data[i+2]*0x100 +  data[i+3];
        if( nTdsPacketLen > 8192 ) {
            i++;
            continue;
        }
        if( nTdsPacketLen == 0 ) {
            i++;
            continue;
        }

        // Found:
        return i;
    }

    return -1;
 }

 static int ReassembleTdsPacket( TdsTransaction *tx, int direction )
 {
    uint32_t nPacketLen = 0;
    struct TdsFragmentPacket_ *pFragment = NULL;
    struct TdsFragmentPacketList *pFragmentList = NULL;

    //const char *strType = NULL;
    pFragmentList = &tx->tdsPackets;
    /*
    if( direction == STREAM_TOSERVER ) {
	    strType = "Request:";
    }
    else {
	    strType = "Reponse:";
    }
    */

    TAILQ_FOREACH(pFragment, pFragmentList, next) {
        nPacketLen += pFragment->nFragmentLen - 8;
    }

    uint8_t *ptr;
    uint8_t *pBuffer = ptr = SCCalloc( nPacketLen, sizeof(uint8_t) );
    TAILQ_FOREACH(pFragment, pFragmentList, next) {
        memcpy( ptr, pFragment->pfragmentBuffer+8, pFragment->nFragmentLen-8 );
        ptr += pFragment->nFragmentLen - 8;
    }

    tx->full_packet_buffer = pBuffer;
    tx->full_packet_len = nPacketLen;

    // Debug:
    //uint8_t* pstr = FetchPrintableString( pBuffer, nPacketLen, '/' );
    //SCLogNotice("Debug: %s", pstr);
    //printf( "%s: %s\n", strType, pstr );
    //SCFree( pstr );

    return 1;
 }

 static int TdsParseRequest(Flow *f, void *state,
     AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
     void *local_data)
 {
     StreamingBufferSegment seg;
     int32_t nHeadOffset = 0;
     TDSState *tds = (TDSState *)state;
     
     SCLogNotice("Parsing TDS request: len=%"PRIu32, input_len);
 
     /* Likely connection closed, we can just return here. */
     if ((input == NULL || input_len == 0) &&
         AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
         return 0;
     }
 
     /* Probably don't want to create a transaction in this case either. */
     if (input == NULL || input_len == 0) {
         return 0;
     }

     if( StreamingBufferAppend( tds->sbRequest , &seg, input, input_len ) < 0 ) {
         return 0;
     }

     do {
        const uint8_t *data = NULL;
        uint32_t data_len = 0;
        uint64_t stream_offset = 0;
        StreamingBufferGetData( tds->sbRequest, &data, &data_len, &stream_offset );
        
        if( data_len == 0 ) {
            break;
        }

   
        /* Try to Match TDS header: 0F 00 | 0F 01 , input_len >= 8 */   
        nHeadOffset = FindTdsHead( data, data_len ); 
        if( nHeadOffset < 0 ) {
            break;
        }
   
        if( nHeadOffset > 0 ) {
            StreamingBufferSlide( tds->sbRequest, nHeadOffset );
        }
        StreamingBufferGetData( tds->sbRequest, &data, &data_len, &stream_offset );
        if( data_len < (8+1) ) {
            break;
        }
        /* Full packet arrived ? */
        uint16_t nTdsPacketLen = data[2]*0x100 +  data[3];
        if( data_len < nTdsPacketLen ) {
            break;
        }
   
        /* Allocate a transaction */
        if( NULL == tds->request_curr ) {
           TdsTransaction *tx = TdsTxAlloc( tds, STREAM_TOSERVER );
           if( NULL == tx ) {
                break;
           }
        }
        
        TdsFragmentPacket *pFragment = SCCalloc( 1, sizeof(TdsFragmentPacket) );
        pFragment->pfragmentBuffer = SCCalloc( nTdsPacketLen, sizeof(uint8_t) );;
        pFragment->nFragmentLen = nTdsPacketLen;
        memcpy( pFragment->pfragmentBuffer, data, nTdsPacketLen );
        TAILQ_INSERT_TAIL(&tds->request_curr->tdsPackets, pFragment, next);  

        if( data[1] == 0x01 ) {
            tds->request_curr->direction = STREAM_TOSERVER;
            tds->request_curr->bComplete = 1;
            ReassembleTdsPacket( tds->request_curr, STREAM_TOSERVER );

            // Start new transaction
            tds->request_curr = NULL;
        }
            
         /* Not all data was processed ? */
         StreamingBufferSlide( tds->sbRequest, nTdsPacketLen );
     }
     while(1);

     return 0;
 }
 
 static int TdsParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
     uint8_t *input, uint32_t input_len, void *local_data)
 {
    StreamingBufferSegment seg;
    int32_t nHeadOffset = 0;
    TDSState *tds = (TDSState *)state;
    
    SCLogNotice("Parsing TDS response: len=%"PRIu32, input_len);

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    if( StreamingBufferAppend( tds->sbResponse , &seg, input, input_len ) < 0 ) {
        return 0;
    }

    do {
       const uint8_t *data = NULL;
       uint32_t data_len = 0;
       uint64_t stream_offset = 0;
       StreamingBufferGetData( tds->sbResponse, &data, &data_len, &stream_offset );
       
       if( data_len == 0 ) {
           break;
       }
  
       /* Try to Match TDS header: 0F 00 | 0F 01 , input_len >= 8 */   
       nHeadOffset = FindTdsHead( data, data_len ); 
       if( nHeadOffset < 0 ) {
           break;
       }
  
       if( nHeadOffset > 0 ) {
           StreamingBufferSlide( tds->sbResponse, nHeadOffset );
       }
       StreamingBufferGetData( tds->sbResponse, &data, &data_len, &stream_offset );
       if( data_len < 8 ) {
            break;
       }
       /* Full packet arrived ? */
       uint16_t nTdsPacketLen = data[2]*0x100 +  data[3];
       if( data_len < nTdsPacketLen ) {
           break;
       }
  
       /* Allocate a transaction */
       if( NULL == tds->reponse_curr ) {
           TdsTransaction *tx = TdsTxAlloc( tds, STREAM_TOCLIENT );
           if( NULL == tx ) {
               break;
            }
        }

       TdsFragmentPacket *pFragment = SCCalloc( 1, sizeof(TdsFragmentPacket) );
       pFragment->pfragmentBuffer = SCCalloc( nTdsPacketLen, sizeof(uint8_t) );;
       pFragment->nFragmentLen = nTdsPacketLen;
       memcpy( pFragment->pfragmentBuffer, data, nTdsPacketLen );
       TAILQ_INSERT_TAIL(&tds->reponse_curr->tdsPackets, pFragment, next);  

       if( data[1] == 0x01 ) {
           tds->reponse_curr->direction = STREAM_TOCLIENT;
           tds->reponse_curr->bComplete = 1;
           ReassembleTdsPacket( tds->reponse_curr, STREAM_TOCLIENT );

           // Start new transaction
           tds->reponse_curr = NULL;
       }
           
        /* Not all data was processed ? */
        StreamingBufferSlide( tds->sbResponse, nTdsPacketLen );
    }
    while(1);
    
    return 0;
 }


 
 void RegisterTdsParsers(void)
 {
     const char *proto_name = "tds";
 
     /* TDS_START_REMOVE */
     if (ConfGetNode("app-layer.protocols.tds") == NULL) {
         return;
     }
     /* TDS_END_REMOVE */
     /* Check if TDS TCP detection is enabled. If it does not exist in
      * the configuration file then it will be enabled by default. */
     if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
 
         SCLogNotice("TDS TCP protocol detection enabled.");
 
         AppLayerProtoDetectRegisterProtocol(ALPROTO_TDS, proto_name);
 
         if (RunmodeIsUnittests()) {
 
             SCLogNotice("Unittest mode, registeringd default configuration.");
             AppLayerProtoDetectPPRegister(IPPROTO_TCP, TDS_DEFAULT_PORT,
                 ALPROTO_TDS, 0, TDS_MIN_FRAME_LEN, STREAM_TOSERVER,
                 TdsProbingParser, NULL);
 
         }
         else {
 
             if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                     proto_name, ALPROTO_TDS, 0, TDS_MIN_FRAME_LEN,
                     TdsProbingParser, NULL)) {
                 SCLogNotice("No echo app-layer configuration, enabling tds"
                     " detection TCP detection on port %s.",
                     TDS_DEFAULT_PORT);
                 AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                     TDS_DEFAULT_PORT, ALPROTO_TDS, 0,
                     TDS_MIN_FRAME_LEN, STREAM_TOSERVER,
                     TdsProbingParser, NULL);
             }
 
         }
 
     }
 
     else {
         SCLogNotice("Protocol detecter and parser disabled for tds.");
         return;
     }
 
     if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
 
         SCLogNotice("Registering TDS protocol parser.");
 
         /* Register functions for state allocation and freeing. A
          * state is allocated for every new Template flow. */
         AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_TDS,
             TdsStateAlloc, TdsStateFree);
 
         /* Register request parser for parsing frame from server to client. */
         AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TDS,
             STREAM_TOSERVER, TdsParseRequest);
 
         /* Register response parser for parsing frames from server to client. */
         AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TDS,
             STREAM_TOCLIENT, TdsParseResponse);
 
         /* Register a function to be called by the application layer
          * when a transaction is to be freed. */
         AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_TDS,
             TdsStateTxFree);
 
         AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_TDS,
             TdsGetTxLogged, TdsSetTxLogged);
 
         /* Register a function to return the current transaction count. */
         AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_TDS,
             TdsGetTxCnt);
 
         /* Transaction handling. */
         AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_TDS,
             TdsGetAlstateProgressCompletionStatus);
         AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP,
             ALPROTO_TDS, TdsGetStateProgress);
         AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_TDS,
             TdsGetTx);
 
         /* Application layer event handling. */
         AppLayerParserRegisterHasEventsFunc(IPPROTO_TCP, ALPROTO_TDS,
             TdsHasEvents);
 
         /* What is this being registered for? */
         AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_TDS,
             NULL, TdsGetTxDetectState, TdsSetTxDetectState);
 
         AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_TDS,
             TdsStateGetEventInfo);
         AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_TDS,
             TdsGetEvents);
     }
     else {
         SCLogNotice("TDS protocol parsing disabled.");
     }
 
 #ifdef UNITTESTS
     AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_TDS,
         TdsParserRegisterTests);
 #endif
 }
 
 #ifdef UNITTESTS
 #endif
 
 void TdsParserRegisterTests(void)
 {
 #ifdef UNITTESTS
 #endif
 }
 







