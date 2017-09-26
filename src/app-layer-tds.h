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

/*

typedef struct ClassA_ {
    TAILQ_ENTRY( ClassA_ ) next;

    int a;
    int b;
}ClassA;

//
//typedef struct QueueClassA_ {
//    struct ClassA_  *tqh_first;
//    struct ClassA_  **tqh_last;
//}QueueClassA;
//

TAILQ_HEAD(QueueClassA,ClassA_) queueClassA;
//QueueClassA queueClassA;

void main(void)
{
    TAILQ_INIT( &queueClassA );
    ClassA *clsA = (ClassA*)calloc(1,sizeof(ClassA));

    *(&queueClassA)->tqh_last = (clsA);

    TAILQ_INSERT_TAIL(&queueClassA, clsA, next);
    ClassA *clsLast = TAILQ_LAST( &queueClassA, QueueClassA );
}
*/


typedef struct TdsFragmentPacket_ {
    TAILQ_ENTRY(TdsFragmentPacket_) next;

    //StreamingBuffer *sb;
    uint8_t *pfragmentBuffer; 
    uint32_t nFragmentLen;
}TdsFragmentPacket;

/* Packet stream input state */
#define TDS_PACKET_STATE_NEW      0
#define TDS_PACKET_STATE_FRAGMENT 1
#define TDS_PACKET_STATE_NEXT     2


typedef struct TdsTransaction_ {
    TAILQ_ENTRY(TdsTransaction_) next;

    uint64_t tx_id;                        /*<< Internal transaction ID. */

    AppLayerDecoderEvents *decoder_events; /*<< Application layer events that occurred while parsing this transaction. */
    uint8_t response_done;                 /*<< Flag to be set when the response is seen. */
    DetectEngineState *de_state;
    uint32_t logged;                        /* flags indicating which loggers that have logged */
              
    /* TDS Connection Info */
    uint32_t nSrcIp;
    uint32_t nSrcPort;
    uint32_t nDestIp;
    uint32_t nDestPort;

    //uint16_t tdsRequestPacketState;
    //uint16_t tdsResponsePacketState;

    TAILQ_HEAD( TdsFragmentPacketList, TdsFragmentPacket_ )  tdsPackets;
    //struct TdsFragmentPacketList tdsRespondsPacket;
    uint8_t bComplete;
    //uint8_t bResponseComplete;

    /* Reassembled tds packet buffer */
    uint8_t direction;
    uint8_t *full_packet_buffer;
    uint32_t full_packet_len;
    //uint8_t *response_buffer;
    //uint32_t response_buffer_len;

}TdsTransaction;

typedef struct TDSState_ {

    TAILQ_HEAD(, TdsTransaction_) tx_list; 

    TdsTransaction *request_curr;                  /**< Current transaction. */
    TdsTransaction *reponse_curr;

    StreamingBufferConfig sbcfg;
    StreamingBuffer *sbRequest;            /* Request buffer for buffering incomplete request PDUs received over TCP. */
    StreamingBuffer *sbResponse;

    uint64_t transaction_max;
    uint16_t events;                       /**< Number of application layer events created for this state. */
    
} TDSState;


void RegisterTdsParsers(void);
void TdsParserRegisterTests(void);

#endif


