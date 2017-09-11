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
/*     
    TDSState *tds_state = state;
    TDSTransaction *tx;
 
     TAILQ_FOREACH(tx, &tds_state->tx_list, next) {
         if (tx->tx_id == tx_id) {
             return tx->decoder_events;
         }
     }
*/ 
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
 
 static void *TdsStateAlloc(void)
 {
     SCLogNotice("Allocating TDS state.");
     TDSState *state = SCCalloc(1, sizeof(TDSState));
     if (unlikely(state == NULL)) {
         return NULL;
     }
     memset( state, 0, sizeof( TDSState ) );

     TAILQ_INIT(&state->tdsRequestPackets);
     TAILQ_INIT(&state->tdsRespondsPackets);
     return state;
 }
 
 static void TdsStateFree(void *state)
 {
     TDSState *tds_state = state;
     SCLogNotice("Freeing TDS state.");

     TdsSessionPacket *pSessionPacket = NULL;
     StreamingBuffer *pStreamBuf = NULL;

     // For Request 
     while ((pSessionPacket = TAILQ_FIRST(&tds_state->tdsRequestPackets)) != NULL) {
         TAILQ_REMOVE(&tds_state->tdsRequestPackets, pSessionPacket, next);

         while((pStreamBuf = TAILQ_FIRST(&pSessionPacket->tdsSessionPacketFragments)) != NULL ) {
            TAILQ_REMOVE(&pSessionPacket->tdsSessionPacketFragments, pStreamBuf, next);
            StreamingBufferFree( pStreamBuf );
         }

         SCFree(pSessionPacket);
     }
     // For Response
     while ((pSessionPacket = TAILQ_FIRST(&tds_state->tdsRespondsPackets)) != NULL) {
        TAILQ_REMOVE(&tds_state->tdsRespondsPackets, pSessionPacket, next);

        while((pStreamBuf = TAILQ_FIRST(&pSessionPacket->tdsSessionPacketFragments)) != NULL ) {
           TAILQ_REMOVE(&pSessionPacket->tdsSessionPacketFragments, pStreamBuf, next);
           StreamingBufferFree( pStreamBuf );
        }

        SCFree(pSessionPacket);
    }


     SCFree(tds_state);
 }
 

/*
TdsSessionDataInput( tdsSessionData, tdsSessionDataLen )
{
    DO WHILE( tdsSessionDataLen > 0 ):
    {
        switch(tdsPacketState)
        {
            case TDS_PACKET_STATE_NEW:
            1. 识别TDS协议数据包头部标记：0F[01|00], 找到TDS协议包头位置：nHeadOffset, bIsLast。如果找不到TDS头部标记，则丢弃收到的数据。
               新建一个tdsSessionPacket：tdsCurrentSessionPacket, 插入tdsSessionPacketList。
            2. 取得TDS协议包的长度：nTdsPacketLen, 确定可以添加到StreamBuffer中的数据长度：nLen=MIN(nTdsPacketLen, tdsSessionDataLen-nHeadOffset)
            3. 新建一个SB: sbTdsPacketCurrent，添加数据到SB：StreamingBufferAppend: sbTdsPacketCurrent, tdsRequestData+nHeadOffset, nLen 
               把新sbTdsPacketCurrent插入当前tdsCurrentSessionPacket链表。 
               nTdsPacketLen -= nLen;           
            4. 如果接收了完整的TDS协议分片包: nTdsPacketLen==0, 保持tdsPacketState为TDS_PACKET_STATE_NEW，准备接收下一个分片数据包。
            5. 如果没有收完一个完整的TDS协议包:nTdsPacketLen!=0，设置tdsPacketState状态：TDS_PACKET_STATE_FRAGMENT，准备接碎片。

            case TDS_PACKET_STATE_FRAGMENT:
            1. nLen = MIN( tdsSessionDataLen, nTdsPacketLen);
            2. 添加数据到SB：StreamingBufferAppend: sbTdsPacketCurrent, tdsRequestData, nLen
            3. nTdsPacketLen -= nLen; 
            4. 如果接收了完整的TDS协议分片包: nTdsPacketLen==0 
                if( bIsLast ) tdsPacketState = TDS_PACKET_STATE_NEW;
                if( !bIsLast ) tdsPacketState = TDS_PACKET_STATE_NEXT;

            case TDS_PACKET_STATE_NEXT:
            1. 识别TDS协议数据包头部标记：0F[01|00], 找到TDS协议包头位置：nHeadOffset, bIsLast。如果找不到TDS头部标记，则丢弃收到的数据。
            2. 取得TDS协议包的长度：nTdsPacketLen, 确定可以添加到StreamBuffer中的数据长度：nLen=MIN(nTdsPacketLen, tdsSessionDataLen-nHeadOffset)
            3. 新建一个SB: sbTdsPacketCurrent，添加数据到SB：StreamingBufferAppend: sbTdsPacketCurrent, tdsRequestData+nHeadOffset, nLen 
               把新sbTdsPacketCurrent插入当前tdsCurrentSessionPacket链表。 
               nTdsPacketLen -= nLen;   
            4. 如果接收了完整的TDS协议分片包: nTdsPacketLen==0, 
               if( bIsLast ) tdsPacketState = TDS_PACKET_STATE_NEW;
               if( !bIsLast ) tdsPacketState = TDS_PACKET_STATE_NEXT;
            5. 如果没有收完一个完整的TDS协议包:nTdsPacketLen!=0，设置tdsPacketState状态：TDS_PACKET_STATE_FRAGMENT，准备接碎片。
        }

        tdsSessionDataLen -= nLen;
        tdsSessionData += nLen;
    }
}
*/
 static int InitTdsPacketList( TDSState *tds, uint8_t *input, uint32_t input_len )
 {
    StreamingBuffer *sb = NULL;
    StreamingBufferSegment seg；
    TdsSessionPacket *tdsSessionPacket = NULL;
    StreamingBufferConfig cfg = { STREAMING_BUFFER_NOFLAGS, 2048, 4096, NULL, NULL, NULL, NULL };
    
    sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);
    
    int nRc = StreamingBufferAppend( sb , &seg, input, input_len )；
    if( nRc < 0 ) 
        return 0;

    tdsSessionPacket = SCCalloc(1, sizeof(TdsSessionPacket));
    TAILQ_INSERT_TAIL(&tdsSessionPacket->tdsSessionPacketFragments, sb, next);
    TAILQ_INSERT_TAIL(&tds->tdsRequestPackets, tdsSessionPacket, next);

    return 1;
 }

 static int InitTdsPacketFragment( TDSState *tds, uint8_t *input, uint32_t input_len )
 {
    StreamingBuffer *sb = NULL;
    StreamingBufferSegment seg；
    TdsSessionPacket *tdsSessionPacket = NULL;
    StreamingBufferConfig cfg = { STREAMING_BUFFER_NOFLAGS, 2048, 4096, NULL, NULL, NULL, NULL };

    tdsSessionPacket = TAILQ_LAST( &tds->tdsRequestPackets, TdsSessionPacket, next );
 
    sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);
    
    int nRc = StreamingBufferAppend( sb , &seg, input, input_len )；
    if( nRc < 0 ) 
        return 0;

    TAILQ_INSERT_TAIL(&tdsSessionPacket->tdsSessionPacketFragments, sb, next);
    return 1;
 }

 static int TdsParseRequest(Flow *f, void *state,
     AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
     void *local_data)
 {
     TdsSessionPacket *tdsSessionPacket = NULL;
     StreamingBuffer *sb = NULL;
     StreamingBufferSegment seg；
     int32_t nHeadOffset = 0, bIsLast = FALSE;
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

     
     //while( input_len > 0 )
     {
         switch( tds->tdsRequestPacketState ){
            case TDS_PACKET_STATE_NEW:
            if( !InitTdsPacketList( tds, input, input_len ) )
                return 0;

            tds->tdsRequestPacketState = TDS_PACKET_STATE_FRAGMENT;
            input_len = 0;
            /*
            Fall Throught
            break;
            */
            case TDS_PACKET_STATE_FRAGMENT:
            if( input_len > 0 ) {
                tdsSessionPacket = TAILQ_LAST( &tds->tdsRequestPackets, TdsSessionPacket, next );
                sb = TAILQ_LAST( &tdsSessionPacket->tdsSessionPacketFragments, StreamingBuffer, next );

                int nRc = StreamingBufferAppend( sb , &seg, input, input_len )；
                if( nRc < 0 ) 
                    return 0;
            }

            const uint8_t *data = NULL;
            uint32_t data_len = 0;
            uint64_t stream_offset = 0;
            StreamingBufferGetData( sb, &data, &data_len, &stream_offset );

            /* Try to Match TDS header: 0F 00 | 0F 01 , input_len >= 8 */
            // ...  
            
            // ...  Found: nHeadOffset >= 0 , Not Found: nHeadOffset < 0 
            if( nHeadOffset < 0 )
                break; 

            {
                // Skip head garbage
                StreamingBufferSlide( sb, nHeadOffset );
                StreamingBufferGetData( sb, &data, &data_len, &stream_offset );
                if( data_len < 8 )
                    break;
                
                /* Full packet arrived ? */
                uint16_t nTdsPacketLen = data[2]*0x100 +  data[3];
                if( data_len >= nTdsPacketLen ) {

                    /* Backup tail data(may be belong to next packet) */
                    const uint8_t *tail_data = NULL;
                    uint32_t tail_data_len = 0;
                    uint8_t *tail_buffer = NULL;
                    if( StreamingBufferGetDataAtOffset ( sb, &tail_data, &tail_data_len, nTdsPacketLen ) ) {
                        tail_buffer = SCCalloc(1, tail_data_len );
                        memcpy( tail_buffer, tail_data, tail_data_len );
                    }

                    /* LAST */
                    if( data[0] == 0x0F && data[1] == 0x01 ) {
                        // log packet info:
                        // 1. reassemble all TDS packets in state->tdsRequestPackets
                        // 2. log packet info 
                        // ...
                        // Free all packets buffered in state->tdsRequestPackets
                        // ...
                        // Reset packet state to TDS_PACKET_STATE_NEW
                        if( data_len > nTdsPacketLen ) {
                            if( StreamingBufferGetDataAtOffset ( sb, &tail_data, &tail_data_len, nTdsPacketLen ) ) {
                                if( !InitTdsPacketList( tds, tail_data, tail_data_len ) )
                                    return 0;
                            }
                        }
                        state->tdsRequestPacketState = TDS_PACKET_STATE_NEW;                            
                    }
                    /* NEXT */
                    else {
                        // Nothing to do but:
                        if( data_len > nTdsPacketLen ) {
                            if( StreamingBufferGetDataAtOffset ( sb, &tail_data, &tail_data_len, nTdsPacketLen ) ) {
                                if( !InitTdsPacketFragment( tds, tail_data, tail_data_len ) )
                                    return 0;
                            }
                        }
                    }
                }
            }
            break;
         }
     }

 end:    
     return 0;
 }
 
 static int TdsParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
     uint8_t *input, uint32_t input_len, void *local_data)
 {
     TDSState *tds = state;
     TDSTransaction *tx = NULL, *ttx;
 
     SCLogNotice("Parsing TDS response.");
 
     /* Likely connection closed, we can just return here. */
     if ((input == NULL || input_len == 0) &&
         AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
         return 0;
     }
 
     /* Probably don't want to create a transaction in this case
      * either. */
     if (input == NULL || input_len == 0) {
         return 0;
     }
 
     /* Look up the existing transaction for this response. In the case
      * of echo, it will be the most recent transaction on the
      * TemplateState object. */
 
     /* We should just grab the last transaction, but this is to
      * illustrate how you might traverse the transaction list to find
      * the transaction associated with this response. */
     TAILQ_FOREACH(ttx, &tds->tx_list, next) {
         tx = ttx;
     }
     
     if (tx == NULL) {
         SCLogNotice("Failed to find transaction for response on echo state %p.", tds);
         goto end;
     }
 
     SCLogNotice("Found transaction %"PRIu64" for response on echo state %p.",
         tx->tx_id, tds);
 
     /* If the protocol requires multiple chunks of data to complete, you may
      * run into the case where you have existing response data.
      *
      * In this case, we just log that there is existing data and free it. But
      * you might want to realloc the buffer and append the data.
      */
     if (tx->response_buffer != NULL) {
         SCLogNotice("WARNING: Transaction already has response data, "
             "existing data will be overwritten.");
         SCFree(tx->response_buffer);
     }
 
     /* Make a copy of the response. */
     tx->response_buffer = SCCalloc(1, input_len);
     if (unlikely(tx->response_buffer == NULL)) {
         goto end;
     }
     memcpy(tx->response_buffer, input, input_len);
     tx->response_buffer_len = input_len;
 
     /* Set the response_done flag for transaction state checking in
      * TdsGetStateProgress(). */
     tx->response_done = 1;
 
 end:
     return 0;
 }
 
 static uint64_t TdsGetTxCnt(void *state)
 {
     TDSState *tds = state;
     SCLogNotice("Current tx count is %"PRIu64".", tds->transaction_max);
     return tds->transaction_max;
 }
 
 static void *TdsGetTx(void *state, uint64_t tx_id)
 {
    TDSState *tds = state;
    TDSTransaction *tx;
 
     SCLogNotice("Requested tx ID %"PRIu64".", tx_id);
 
     TAILQ_FOREACH(tx, &tds->tx_list, next) {
         if (tx->tx_id == tx_id) {
             SCLogNotice("Transaction %"PRIu64" found, returning tx object %p.",
                 tx_id, tx);
             return tx;
         }
     }
 
     SCLogNotice("Transaction ID %"PRIu64" not found.", tx_id);
     return NULL;
 }
 
 static void TdsSetTxLogged(void *state, void *vtx, uint32_t logger)
 {
     TDSTransaction *tx = (TDSTransaction *)vtx;
     tx->logged |= logger;
 }
 
 static int TdsGetTxLogged(void *state, void *vtx, uint32_t logger)
 {
     TDSTransaction *tx = (TDSTransaction *)vtx;
     if (tx->logged & logger)
         return 1;
 
     return 0;
 }
 
 /**
  * \brief Called by the application layer.
  *
  * In most cases 1 can be returned here.
  */
 static int TdsGetAlstateProgressCompletionStatus(uint8_t direction) {
     return 1;
 }
 
 /**
  * \brief Return the state of a transaction in a given direction.
  *
  * In the case of the echo protocol, the existence of a transaction
  * means that the request is done. However, some protocols that may
  * need multiple chunks of data to complete the request may need more
  * than just the existence of a transaction for the request to be
  * considered complete.
  *
  * For the response to be considered done, the response for a request
  * needs to be seen.  The response_done flag is set on response for
  * checking here.
  */
 static int TdsGetStateProgress(void *tx, uint8_t direction)
 {
    TDSTransaction *tdstx = (TDSTransaction *)tx;
 
     SCLogNotice("Transaction progress requested for tx ID %"PRIu64
         ", direction=0x%02x", tdstx->tx_id, direction);
 
     if (direction & STREAM_TOCLIENT && tdstx->response_done) {
         return 1;
     }
     else if (direction & STREAM_TOSERVER) {
         /* For echo, just the existence of the transaction means the
          * request is done. */
         return 1;
     }
 
     return 0;
 }
 
 /**
  * \brief ???
  */
 static DetectEngineState *TdsGetTxDetectState(void *vtx)
 { 
     TDSTransaction *tx = vtx;
     return tx->de_state;
 }
 
 /**
  * \brief ???
  */
 static int TdsSetTxDetectState(void *state, void *vtx,
     DetectEngineState *s)
 {
     TDSTransaction *tx = vtx;
     tx->de_state = s;
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
         SCLogNotice("Protocol detecter and parser disabled for Template.");
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
 







