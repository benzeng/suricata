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
 
 static TDSTransaction *TdsTxAlloc(TDSState *tds)
 {
    TDSTransaction *tx = SCCalloc(1, sizeof(TDSTransaction));
     if (unlikely(tx == NULL)) {
         return NULL;
     }
 
     /* Increment the transaction ID on the state each time one is
      * allocated. */
     tx->tx_id = tds->transaction_max++;
 
     TAILQ_INSERT_TAIL(&tds->tx_list, tx, next);
 
     return tx;
 }
 
 static void TdsTxFree(void *tx)
 {
    TDSTransaction *tdstx = (TDSTransaction *)tx;
 
     if (tdstx->request_buffer != NULL) {
         SCFree(tdstx->request_buffer);
     }
 
     if (tdstx->response_buffer != NULL) {
         SCFree(tdstx->response_buffer);
     }
 
     AppLayerDecoderEventsFreeEvents(&tdstx->decoder_events);
 
     SCFree(tx);
 }
 
 static void *TdsStateAlloc(void)
 {
     SCLogNotice("Allocating TDS state.");
     TDSState *state = SCCalloc(1, sizeof(TDSState));
     if (unlikely(state == NULL)) {
         return NULL;
     }
     TAILQ_INIT(&state->tx_list);
     return state;
 }
 
 static void TdsStateFree(void *state)
 {
     TDSState *tds_state = state;
     TDSTransaction *tx;
     SCLogNotice("Freeing TDS state.");
     while ((tx = TAILQ_FIRST(&tds_state->tx_list)) != NULL) {
         TAILQ_REMOVE(&tds_state->tx_list, tx, next);
         TdsTxFree(tx);
     }
     SCFree(tds_state);
 }
 
 /**
  * \brief Callback from the application layer to have a transaction freed.
  *
  * \param state a void pointer to the TdsState object.
  * \param tx_id the transaction ID to free.
  */
 static void TdsStateTxFree(void *state, uint64_t tx_id)
 {
     TDSState *tds = (TDSState *)state;
     TDSTransaction *tx = NULL, *ttx;
 
     SCLogNotice("Freeing transaction %"PRIu64, tx_id);
 
     TAILQ_FOREACH_SAFE(tx, &tds->tx_list, next, ttx) {
 
         /* Continue if this is not the transaction we are looking
          * for. */
         if (tx->tx_id != tx_id) {
             continue;
         }
 
         /* Remove and free the transaction. */
         TAILQ_REMOVE(&tds->tx_list, tx, next);
         TdsTxFree(tx);
         return;
     }
 
     SCLogNotice("Transaction %"PRIu64" not found.", tx_id);
 }
 
 static int TdsStateGetEventInfo(const char *event_name, int *event_id,
     AppLayerEventType *event_type)
 {
     *event_id = SCMapEnumNameToValue(event_name, template_decoder_event_table);
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
    TDSTransaction *tx;
 
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
  * \brief Probe the input to see if it looks like echo.
  *
  * \retval ALPROTO_TDS if it looks like echo, otherwise
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
 
 static int TdsParseRequest(Flow *f, void *state,
     AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
     void *local_data)
 {
     TDSState *tds = (TDSState *)state;
 
     SCLogNotice("Parsing TDS request: len=%"PRIu32, input_len);
 
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
 
     /* Normally you would parse out data here and store it in the
      * transaction object, but as this is echo, we'll just record the
      * request data. */
 
     /* Also, if this protocol may have a "protocol data unit" span
      * multiple chunks of data, which is always a possibility with
      * TCP, you may need to do some buffering here.
      *
      * For the sake of simplicity, buffering is left out here, but
      * even for an echo protocol we may want to buffer until a new
      * line is seen, assuming its text based.
      */
 
     /* Allocate a transaction.
      *
      * But note that if a "protocol data unit" is not received in one
      * chunk of data, and the buffering is done on the transaction, we
      * may need to look for the transaction that this newly recieved
      * data belongs to.
      */
     TDSTransaction *tx = TdsTxAlloc(tds);
     if (unlikely(tx == NULL)) {
         SCLogNotice("Failed to allocate new TDS tx.");
         goto end;
     }
     SCLogNotice("Allocated TDS tx %"PRIu64".", tx->tx_id);
     
     /* Make a copy of the request. */
     tx->request_buffer = SCCalloc(1, input_len);
     if (unlikely(tx->request_buffer == NULL)) {
         goto end;
     }
     memcpy(tx->request_buffer, input, input_len);
     tx->request_buffer_len = input_len;
 
     /* Here we check for an TDS message and create an app-layer
      * event. */
     if ((input_len == 1 && tx->request_buffer[0] == '\n') ||
         (input_len == 2 && tx->request_buffer[0] == '\r')) {
         SCLogNotice("Creating event for empty message.");
         AppLayerDecoderEventsSetEventRaw(&tx->decoder_events,
             TDS_DECODER_EVENT_EMPTY_MESSAGE);
         echo->events++;
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
    TDSTransaction *tds = state;
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
                 SCLogNotice("No echo app-layer configuration, enabling echo"
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
             TemplateHasEvents);
 
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
 







