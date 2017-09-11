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


typedef struct TdsSessionPacket_ {
    TAILQ_HEAD(, StreamingBuffer) tdsSessionPacketFragments;
    TAILQ_ENTRY(TdsSessionPacket_) next;
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
    TAILQ_HEAD(, TdsSessionPacket)  tdsRequestPackets;
    TAILQ_HEAD(, TdsSessionPacket)  tdsRespondsPackets;

} TDSState;


void RegisterTdsParsers(void);
void TdsParserRegisterTests(void);

#endif


