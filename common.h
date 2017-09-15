//
// Created by Sai Jiang on 17/9/7.
//

#ifndef RTP_COMMON_H
#define RTP_COMMON_H

#include "GenericQueue.h"
#include <kodoc/kodoc.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdbool.h>

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#define debug(fmt, ...) \
        do { fprintf(stderr, "%s()=> " fmt, __func__, __VA_ARGS__); } while (0)

#define DST_IP      "127.0.0.1"
#define DST_DPORT   7777
#define DST_SPORT   8888

#define MAXSYMBOL       (1024)
#define MAXSYMBOLSIZE   (1024)

#define LOOPCNT         (2000)

#define EXTRAPERCENT    (0.02)

// Original Data Wrapper-related Begin
typedef struct {
    iqueue_head qnode;
    uint32_t datlen;
//    uint32_t seqid;
    uint8_t data[0];
} SrcData;
// Original Data Wrapper-related End

typedef SrcData DstData;

// Encoder-related Begin
typedef enum {
    GatherMode,
    FountainMode,
    WaitNSeeMode,
    FinishMode,
} EncState;

typedef struct {
    uint32_t id;
    kodoc_coder_t enc;
    EncState state;
    SrcData *pdat; // encoded data
    iqueue_head qnode;
} EncWrapper;
// Encoder-related End


// ACK-related Begin
typedef enum {
    PrimaryACK,
    NACK,
    FinalACK,
} AckType;

typedef struct {
    uint32_t id;
    AckType type;
} AckMsg;
// ACK-related End


// Pkt-related Begin
typedef struct {
    uint32_t encid;
    uint8_t data[0];
} Packet;
// Pkt-related End


// Transmitter-related Begin
typedef struct {
    iqueue_head src_queue;

    kodoc_factory_t enc_factory;

    int maxsymbol, maxsymbolsize, blksize;

    iqueue_head enc_queue;
    uint32_t  NxtEncID;

    Packet *pktbuf;
    uint32_t payload_size;

    int SignalSock, DataSock;

} Transmitter;
// Transmitter-related End


typedef struct {
    iqueue_head qnode;
    Packet *pkt;
} ChainedPkt;

typedef struct {
    iqueue_head qnode;

    uint32_t NRecvedPkts;

    bool SentPrimaryACK;
    bool HasRecvedNxtBatchPkts;
    bool SentFinalACK;

    kodoc_coder_t dec;
    SrcData *pdat;

    uint32_t id;

} DecWrapper;


// Receiver-related Begin
typedef struct {
    Packet *pktbuf;
    uint32_t payload_size;

    iqueue_head pkt_queue;
    uint32_t FinalACKedNUpdatedF;

    kodoc_factory_t dec_factory;

    int maxsymbol, maxsymbolsize, blksize;

    uint32_t F, N;

    iqueue_head dec_queue;

    iqueue_head dst_queue;
    uint32_t UsrRcvNxt;

    int SignalSock, DataSock;
} Receiver;
// Receiver-related End




#endif //RTP_COMMON_H
