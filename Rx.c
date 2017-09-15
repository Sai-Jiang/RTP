#include "common.h"

static const int32_t codec = kodoc_sparse_seed;

Receiver * Receiver_Init(int maxsymbols, int maxsymbolsize)
{
    Receiver *rx = malloc(sizeof(Receiver));

    rx->dec_factory = kodoc_new_decoder_factory(codec, kodoc_binary8,
                                                maxsymbols, maxsymbolsize);
    rx->maxsymbol = maxsymbols;
    rx->maxsymbolsize = maxsymbolsize;
    rx->blksize = rx->maxsymbol * rx->maxsymbolsize;

    rx->payload_size = kodoc_factory_max_payload_size(rx->dec_factory);
    rx->pktbuf = malloc(sizeof(Packet) + rx->payload_size);

    iqueue_init(&rx->pkt_queue);
    rx->FinalACKedNUpdatedF = 0;

    rx->N = (uint32_t )(maxsymbols * (1 + EXTRAPERCENT));
    rx->F = rx->N / 2;

    iqueue_init(&rx->dec_queue);

    iqueue_init(&rx->dst_queue);
    rx->UsrRcvNxt = 0;

    {
        int tcpsock = socket(PF_INET, SOCK_STREAM, 0);

        int opt = 1;
        setsockopt(tcpsock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htons(INADDR_ANY);
        addr.sin_port = htons(DST_SPORT);

        if (bind(tcpsock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            printf("tcpsock Bind Failed\n");
            assert(true);
        }

        listen(tcpsock, 128);

        rx->SignalSock = accept(tcpsock, NULL, NULL);
    }

    {
        rx->DataSock = socket(PF_INET, SOCK_DGRAM, 0);

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htons(INADDR_ANY);
        addr.sin_port = htons(DST_DPORT);

        if (bind(rx->DataSock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            printf("DataChannel Bind Failed\n");
            assert(true);
        }

        // DataSock Nonblocking Read
        int flags = fcntl(rx->DataSock, F_GETFL, 0);
        fcntl(rx->DataSock, F_SETFL, flags | O_NONBLOCK);
    }

    return rx;
}

void Receiver_Release(Receiver *rx)
{
    kodoc_delete_factory(rx->dec_factory);

    free(rx->pktbuf);

    close(rx->DataSock);
    close(rx->SignalSock);

    free(rx);
}

void CheckData(Receiver *rx)
{
    int nbytes, pktbuflen = sizeof(Packet) + rx->payload_size;

    // Nonblocking Read
    while ((nbytes = read(rx->DataSock, rx->pktbuf, pktbuflen)) > 0) {
        assert(nbytes == sizeof(Packet) + rx->payload_size);
        if (rx->pktbuf->encid < rx->FinalACKedNUpdatedF) continue;

        // construct a Chained Packet node
        ChainedPkt *cpkt = malloc(sizeof(ChainedPkt));
        cpkt->pkt = malloc(pktbuflen);
        memcpy(cpkt->pkt, rx->pktbuf, pktbuflen);

        if (iqueue_is_empty(&rx->pkt_queue)) {
            iqueue_add_tail(&cpkt->qnode, &rx->pkt_queue);
        } else {
            for (iqueue_head *p = rx->pkt_queue.next, *nxt; p != &rx->pkt_queue; p = nxt) {
                nxt = p->next;
                ChainedPkt *entry = iqueue_entry(p, ChainedPkt, qnode);

                // filter out out-of-time packet
                if (entry->pkt->encid < rx->FinalACKedNUpdatedF) {
                    iqueue_del(&entry->qnode);
                    free(cpkt->pkt);
                    free(cpkt);
                }

                // Insert before the 'p' packet
                if (entry->pkt->encid >= cpkt->pkt->encid) {
                    cpkt->qnode.prev = p->prev;
                    cpkt->qnode.next = p;
                    p->prev = &cpkt->qnode;
                    (cpkt->qnode.prev)->next = &cpkt->qnode;
                    break;
                }
            }
        }
    }
}

void MovPkt2Dec(Receiver *rx)
{
    while (!iqueue_is_empty(&rx->pkt_queue)) {
        IQUEUE_HEAD(sameid);
        uint32_t id = (iqueue_entry(rx->pkt_queue.next, ChainedPkt, qnode))->pkt->encid;
        int npkts = 0;

        // detach a list of packets of the same id, at least one
        for (iqueue_head *p = rx->pkt_queue.next, *nxt; p != &rx->pkt_queue; p = nxt) {
            nxt = p->next;
            ChainedPkt *cpkt = iqueue_entry(p, ChainedPkt, qnode);
            if (cpkt->pkt->encid == id) {
                iqueue_del(p);
                iqueue_add_tail(p, &sameid);
                npkts++;
            }
        }

        // if no decoder exists or this is the packet from new batch,
        // allocate another decoder
        if (iqueue_is_empty(&rx->dec_queue) ||
                ((iqueue_entry(rx->dec_queue.prev, DecWrapper, qnode))->id < id)) {
            DecWrapper *newdecwrapper = malloc(sizeof(DecWrapper));
            newdecwrapper->NRecvedPkts = 0;
            newdecwrapper->SentPrimaryACK = false;
            newdecwrapper->HasRecvedNxtBatchPkts = false;
            newdecwrapper->SentFinalACK = false;
            newdecwrapper->id = id;
            newdecwrapper->dec = kodoc_factory_build_coder(rx->dec_factory);
            newdecwrapper->pdat = malloc(sizeof(SrcData) + kodoc_block_size(newdecwrapper->dec));
            newdecwrapper->pdat->datlen = kodoc_block_size(newdecwrapper->dec);
            kodoc_set_mutable_symbols(newdecwrapper->dec, newdecwrapper->pdat->data,
                                      kodoc_block_size(newdecwrapper->dec));
            iqueue_add_tail(&newdecwrapper->qnode, &rx->dec_queue);
        }

        DecWrapper *decwrapper = NULL;
        iqueue_foreach(decwrapper, &rx->dec_queue, DecWrapper, qnode) {
            if (decwrapper->id < id) {
                if (decwrapper->HasRecvedNxtBatchPkts == false) {
                    decwrapper->HasRecvedNxtBatchPkts = true;
                    int threshold = min(max(((int)rx->N - (int)rx->F), 0), (int)rx->maxsymbol);
                    debug("N: %u, Fold: %u\n", rx->N, rx->F);
                    debug("NRecvedPkts: %u, threshold: %u\n", decwrapper->NRecvedPkts, threshold);
                    if ((int)decwrapper->NRecvedPkts < threshold) {
                        debug("PrimaryACK: %s\n", decwrapper->SentPrimaryACK ? "True" : "False");
                        debug("decwrapper->id: %u, id: %u\n", decwrapper->id, id);
                    }

                    assert((int)decwrapper->NRecvedPkts >= threshold);
                    uint32_t Fnew = decwrapper->NRecvedPkts - threshold;
                    rx->F = (1 - 0.5) * rx->F + 0.5 * Fnew;
                    debug("Fnew: %u, Fsmooth: %u\n", Fnew, rx->F);

                    if (decwrapper->SentFinalACK == false) {
                        AckMsg msg = {decwrapper->id, NACK};
                        send(rx->SignalSock, &msg, sizeof(msg), 0);
                    }
                }
            } else if (decwrapper->id == id) {
                for (iqueue_head *p = sameid.next, *nxt; p != &sameid; p = nxt) {
                    nxt = p->next;
                    ChainedPkt *cpkt = iqueue_entry(p, ChainedPkt, qnode);

                    if (!kodoc_is_complete(decwrapper->dec))
                        kodoc_read_payload(decwrapper->dec, cpkt->pkt->data);
                    decwrapper->NRecvedPkts++;

                    npkts--;
                    iqueue_del(p);
                    free(cpkt->pkt);
                    free(cpkt);

                    int threshold = min(max(((int)rx->N - (int)rx->F), 0), (int)rx->maxsymbol);
                    if (decwrapper->NRecvedPkts >= threshold && !decwrapper->SentPrimaryACK) {
                        decwrapper->SentPrimaryACK = true;
                        AckMsg msg = {id, PrimaryACK};
                        send(rx->SignalSock, &msg, sizeof(msg), 0);
                    }

                    if (kodoc_is_complete(decwrapper->dec) && !decwrapper->SentFinalACK) {
                        decwrapper->SentFinalACK = true;
                        AckMsg msg = {id, FinalACK};
                        send(rx->SignalSock, &msg, sizeof(msg), 0);
                        // add the decoded block into the queue, waiting for fetch by user
                        // However, for now, leave the job to the 'FinalACKedNUpdatedF' Update
                    }
                }

                break;
            } else {
                // what if we can't find a right one encoder and
                // the id is not the largest one?
                printf("Unknown Error !!\n");
                assert(true);
            }
        }

        // Update FinalACKedNUpdatedF and free the oldest unused decoder
        decwrapper = iqueue_entry(rx->dec_queue.next, DecWrapper, qnode);
        if (decwrapper->id == rx->FinalACKedNUpdatedF &&
            decwrapper->HasRecvedNxtBatchPkts && decwrapper->SentFinalACK) {
            // Transfer the recovered block to the upper level
            iqueue_add_tail(&decwrapper->pdat->qnode, &rx->dst_queue);
            rx->FinalACKedNUpdatedF++;
            iqueue_head *entry = rx->dec_queue.next;
            iqueue_del(entry);
            kodoc_delete_coder(decwrapper->dec);
//            free(decwrapper->pdat);
            free(decwrapper);
        }
    }
}

int Recv(Receiver *rx, void *buf, size_t buflen)
{
    if (iqueue_is_empty(&rx->dst_queue)) return 0;

    SrcData *sd = iqueue_entry(rx->dst_queue.next, SrcData, qnode);
    iqueue_head *entry = rx->dst_queue.next;
    iqueue_del(entry);
    assert(sd->datlen == buflen);
    memcpy(buf, sd->data, buflen);
    free(sd);

    return buflen;
}

int main()
{
    Receiver *rx = Receiver_Init(MAXSYMBOL, MAXSYMBOLSIZE);

    void *buf = malloc(rx->blksize);
    void *cmp = malloc(rx->blksize);
    int loopcnt = 0;

    do {
        CheckData(rx);
        MovPkt2Dec(rx);
        int nbytes = Recv(rx, buf, rx->blksize);
        if (nbytes > 0) {
            assert(nbytes == rx->blksize);
            memset(cmp, 'a' + loopcnt, rx->blksize);
            assert(memcmp(buf, cmp, rx->blksize) == 0);
            printf("One block Done: %d\n\n", loopcnt);
            loopcnt++;
        }
    } while (!iqueue_is_empty(&rx->pkt_queue) || !iqueue_is_empty(&rx->dec_queue) ||
            !iqueue_is_empty(&rx->dst_queue) || loopcnt < LOOPCNT);

    printf("Receiver Done\n");

    Receiver_Release(rx);

    free(buf);
    free(cmp);
}