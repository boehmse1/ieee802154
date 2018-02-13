//
// Copyright (C) 2017 Christoph Schwalbe (original code)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#ifndef IEEE802154EXTINTERFACE_H_
#define IEEE802154EXTINTERFACE_H_

#pragma once

#include <platdep/sockets.h>
#include <omnetpp.h>
#include <platdep/timeutil.h>

#include <omnetpp.h>
#include "Buffer.h"
#include "RawPacket.h"
#include "MPDU_m.h"
#include "PPDU_m.h"
#include "MACAddressExt.h"
#include "IEEE802154Enum.h"
#include "IEEE802154Serializer.h"

// only for debug
#include <sstream>
#include <string>
// only for debug and module path name discovery

#include "PCAPNGReader.h"
#include "pcapng.h"
#include "PCAPRTScheduler.h"


/*
 * Interface of extern Node receiving Data (IEEE802154 Frames) via Socket communication, through cRTScheduler
 */
class IEEE802154ExtInterface : public cSimpleModule
{
  protected:
    //has to be redefined to prevent memory leak/protection access with them
    cMessage *rtEvent;                  /* new items received at RTScheduler, for event trigger */
    PCAPRTScheduler *rtScheduler; /* access to real network interface via Scheduler class */
    cMessage *initEvent;  // signals that a pcap File Header Frame has complete arrived in Buffer

    //simsignal_t     arrivalSignal;
    //simtime_t zeitmessung[100];
    //int zaehler;


    mpdu *IEEE802154_Frame;
    cModule *targetModule;
    std::map<int, int> interfaceTable;  //interface_id = moduleid

    MACAddressExt *ext;
    Buffer *b;
    //Context c;

    std::stringstream strstr;
    IEEE802154Serializer *s;

    PCAPNGReader *r;
    block_header curr_block;

    // statistics
    int numSent;
    int numRcvd;
    int numDropped;

    unsigned char recvBuffer[65536]; //1<<16 or 2^16 , shift is maybe faster = 2^16 = 65536 = 1<<16
    unsigned int recvPos;
    int numRecvBytes;
    unsigned int BytesLeft;                                           //FIXME: clean obsolet stuff

    unsigned char *beginPayloadptr;
    unsigned char *endPayloadptr;                                      //FIXME: clean obsolet stuff

    unsigned char payload[128];
    unsigned int remainingPayloadBytes;

    //int addr;
    //int srvAddr;


  public:
    IEEE802154ExtInterface();
    virtual ~IEEE802154ExtInterface();
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
    void handleEPB(cMessage *msg);
    void handleReply(cMessage *msg);

    void showFrameContent(mpdu *mp);



    // ****** Misc ******** //
    inline bpf_u_int32 read2Bytes(unsigned char * buf, int from)
    {
        bpf_u_int32 value = 0;

        value = buf[from];
        value = (value & 0xFF) << 8;
        value = (value | buf[from + 1]);
        return value;
    }

    inline bpf_u_int32 read4Bytes(unsigned char * buf, int from)
    {
        bpf_u_int32 value = 0;

        value = buf[from];
        value = (value & 0xFF) << 8;
        value = (value | buf[from + 1]);
        value = (value & 0xFFFF) << 8;
        value = (value | buf[from + 2]);
        value = (value & 0xFFFFFF) << 8;
        value = (value | buf[from + 3]);
        return value;
    }

    inline void write4Bytes(unsigned char * buf, int at, uint32 value){
            buf[at]   = (value & 0xFF); std::cout << (buf[at] & 0xFF) << " ";
            buf[at+1] = (value & 0xFF00)>>8; std::cout << (buf[at+1] & 0xFF) << " ";
            buf[at+2] = (value & 0xFF0000)>>16; std::cout << (buf[at+2] & 0xFF) << " ";
            buf[at+3] = (value & 0xFF000000)>>24; std::cout << (buf[at+3] & 0xFF) << endl;
    }
};

#endif /* IEEE802154EXTINTERFACE_H_ */
