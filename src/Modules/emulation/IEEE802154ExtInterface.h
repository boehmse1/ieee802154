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


#define extEV (ev.isDisabled()) ? std::cout : std::cout << "[IEEE802154ExtInterface]: "    // switchable debug output

/*
 * Dispatching IEEE802154 Interface
 */
class IEEE802154ExtInterface : public cSimpleModule
{
  protected:
    //has to be redefined to prevent memory leak/protection access with them
    cMessage *rtEvent;                  /* new items received at RTScheduler, for event trigger */
    PCAPRTScheduler *rtScheduler; /* access to real network interface via Scheduler class */
    cMessage *initEvent;  // signals that a pcap File Header Frame has complete arrived in Buffer


    mpdu *IEEE802154_Frame;
    cModule *targetModule;
    std::map<int, int> interfaceTable;  //interface_id = moduleid

    MACAddressExt *ext;
    Buffer *b;

    std::stringstream strstr;
    IEEE802154Serializer *s;

    PCAPNGReader *r;
    block_header curr_block;

    // statistics
    int numSent;
    int numRcvd;
    int numDropped;

    unsigned char recvBuffer[1<<16];
    unsigned int recvPos;
    int numRecvBytes;
    unsigned int BytesLeft;                                           //FIXME: clean obsolet stuff

    unsigned char *beginPayloadptr;
    unsigned char *endPayloadptr;                                      //FIXME: clean obsolet stuff

    unsigned char payload[128];
    unsigned int remainingPayloadBytes;


  public:
    IEEE802154ExtInterface();
    virtual ~IEEE802154ExtInterface();
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
    void handleEPB(cMessage *msg);
    void handleReply(cMessage *msg);

};

#endif /* IEEE802154EXTINTERFACE_H_ */
