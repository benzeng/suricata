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

typedef struct StreamingBufferNode_ {
    StreamingBuffer *sb;
    TAILQ_ENTRY(StreamingBufferNode_) next;
}StreamingBufferNode;


typedef struct TdsSessionPacket_ {
    TAILQ_ENTRY(TdsSessionPacket_) next;

    TAILQ_HEAD( StreamingBufferNodeList, StreamingBufferNode_ ) tdsSessionPacketFragments;
}TdsSessionPacket;

/* Packet stream input state */
#define TDS_PACKET_STATE_NEW      0
#define TDS_PACKET_STATE_FRAGMENT 1
#define TDS_PACKET_STATE_NEXT     2


typedef struct TDSState_ {

    StreamingBufferConfig sbcfg;

    uint16_t events;                       /**< Number of application layer events created for this state. */
    AppLayerDecoderEvents *decoder_events; /*<< Application layer events that occurred while parsing this transaction. */
    uint8_t response_done;                 /*<< Flag to be set when the response is seen. */
    DetectEngineState *de_state;
    uint32_t logged;                        /* flags indicating which loggers that have logged */
              
    /* TDS Connection Info */
    uint32_t SrcIp;
    uint32_t SrcPort;
    uint32_t DestIp;
    uint32_t DestPort;

    uint16_t tdsRequestPacketState;
    uint16_t tdsResponsePacketState;

    TAILQ_HEAD( TdsSessionPacketList, TdsSessionPacket_ )  tdsRequestPackets;
    TAILQ_HEAD( , TdsSessionPacket_ )  tdsRespondsPackets;

} TDSState;


void RegisterTdsParsers(void);
void TdsParserRegisterTests(void);

#endif


