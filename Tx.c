#include "common.h"

static const int32_t codec = kodoc_sparse_seed;

Transmitter *Transmitter_Init(int maxsymbols, int maxsymbolsize)
{
    Transmitter *tx = malloc(sizeof(Transmitter));

    iqueue_init(&tx->src_queue);

    tx->enc_factory = kodoc_new_encoder_factory(
            codec, kodoc_binary8, maxsymbols, maxsymbolsize);

    tx->maxsymbol = maxsymbols;
    tx->maxsymbolsize = maxsymbolsize;
    tx->blksize = tx->maxsymbol * tx->maxsymbolsize;

    iqueue_init(&tx->enc_queue);
    tx->NxtEncID = 0;

    tx->payload_size = kodoc_factory_max_payload_size(tx->enc_factory);
    tx->pktbuf = malloc(sizeof(Packet) + tx->payload_size);
    assert(tx->payload_size < 1500);

    {
        // Init SignalSock Begin
        tx->SignalSock = socket(PF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        inet_pton(PF_INET, DST_IP, &addr.sin_addr);
        addr.sin_family = AF_INET;
        addr.sin_port = htons(DST_SPORT);
        connect(tx->SignalSock, (struct sockaddr *) &addr, sizeof(addr));
        int flags = fcntl(tx->SignalSock, F_GETFL, 0);
        fcntl(tx->SignalSock, F_SETFL, flags | O_NONBLOCK);
        // Init SignalSock End
    }

    {
        // Init DataSock Begin
        tx->DataSock = socket(PF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        inet_pton(PF_INET, DST_IP, &addr.sin_addr);
        addr.sin_family = AF_INET;
        addr.sin_port = htons(DST_DPORT);
        connect(tx->DataSock, (struct sockaddr *) &addr, sizeof(addr));
        // Init DataSock End
    }

    return tx;
}

void Transmitter_Release(Transmitter *tx)
{
    assert(iqueue_is_empty(&tx->src_queue));

    kodoc_delete_factory(tx->enc_factory);

    assert(iqueue_is_empty(&tx->enc_queue));

    free(tx->pktbuf);

    close(tx->DataSock);
    close(tx->SignalSock);

    free(tx);
}

void Send(Transmitter *tx, void *buf, size_t buflen)
{
    SrcData *inserted = malloc(sizeof(SrcData) + buflen);
    memcpy(inserted->data, buf, buflen);
    inserted->datlen = buflen;

    iqueue_add_tail(&inserted->qnode, &tx->src_queue);
}

void MoveSrc2Enc(Transmitter *tx)
{
    while (!iqueue_is_empty(&tx->src_queue)) {
        SrcData *sd = iqueue_entry(tx->src_queue.next, SrcData, qnode);
        iqueue_del(&sd->qnode);

        EncWrapper *encwrapper = malloc(sizeof(EncWrapper));
        encwrapper->enc = kodoc_factory_build_coder(tx->enc_factory);
        encwrapper->id = tx->NxtEncID++;
        encwrapper->state = FountainMode;
        encwrapper->pdat = sd;
        assert(sd->datlen == kodoc_block_size(encwrapper->enc));
        kodoc_set_const_symbols(encwrapper->enc, sd->data, sd->datlen);
        iqueue_add_tail(&encwrapper->qnode, &tx->enc_queue);
    }
}

void CheckACK(Transmitter *tx)
{
    AckMsg msg;

    // assume no loop is needed for now. NonBlocking Read
    int nbytes = read(tx->SignalSock, &msg, sizeof(msg));
    if (nbytes <= 0) return;

    assert(nbytes == sizeof(msg));

    EncWrapper *encwrapper = NULL;
    iqueue_foreach(encwrapper, &tx->enc_queue, EncWrapper, qnode) {
        if (msg.id > encwrapper->id) continue;
        else if (msg.id < encwrapper->id) break;
        else {
            assert(msg.id == encwrapper->id);
            switch (msg.type) {
                case PrimaryACK:
                    assert(encwrapper->state == FountainMode);
                    encwrapper->state = WaitNSeeMode;
                    printf("Enc: %u, %s\n", encwrapper->id, "PrimaryACK");
                    break;
                case NACK:
                    assert(encwrapper->state == WaitNSeeMode);
                    encwrapper->state = FountainMode;
                    printf("Enc: %u, %s\n", encwrapper->id, "NACK");
                    break;
                case FinalACK:
                    assert(encwrapper->state == FountainMode ||
                            encwrapper->state == WaitNSeeMode);
                    encwrapper->state = FinishMode;
                    printf("Enc: %u, %s\n", encwrapper->id, "FinalACK");
                    break;
                default:
                    assert(msg.type == PrimaryACK ||
                           msg.type == NACK ||
                           msg.type == FinalACK);
            }

            break;
        }
    }
}

void Fountain(Transmitter *tx)
{
    EncWrapper *encwrapper = NULL;

    for (iqueue_head *p = tx->enc_queue.next, *nxt; p != &tx->enc_queue; p = nxt) {
        nxt = p->next;
        encwrapper = iqueue_entry(p, EncWrapper, qnode);

        if (encwrapper->state == FountainMode) break;
        else if (encwrapper->state == FinishMode) {
            iqueue_del(&encwrapper->qnode);
            kodoc_delete_coder(encwrapper->enc);
            free(encwrapper->pdat);
            free(encwrapper);
        }
    }

    if (encwrapper && encwrapper->state == FountainMode) {
        assert(tx->payload_size == kodoc_payload_size(encwrapper->enc));
        tx->pktbuf->encid = encwrapper->id;
        kodoc_write_payload(encwrapper->enc, tx->pktbuf->data);
        send(tx->DataSock, tx->pktbuf, sizeof(Packet) + tx->payload_size, 0);
    }
}

int main()
{
    Transmitter *tx = Transmitter_Init(MAXSYMBOL, MAXSYMBOLSIZE);

    uint8_t *blk = malloc(tx->blksize);
    int blkcnt = 0;

    do {
        if (blkcnt < LOOPCNT + 1) {
            memset(blk, 'a' + blkcnt, tx->blksize);
            Send(tx, blk, tx->blksize);
            blkcnt++;
        }

        MoveSrc2Enc(tx);
        CheckACK(tx);
        Fountain(tx);
    } while (!iqueue_is_empty(&tx->src_queue) || !iqueue_is_empty(&tx->enc_queue));

    free(blk);

    Transmitter_Release(tx);
}