//
// Copyright (C) 2017 Christoph Schwalbe (original code)
// Copyright (C) 2018 Sebastian Boehm (BTU-CS) (fundamental changes in message passing and handling)
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
#include <regex>
// only for debug and module path name discovery

#include "pcapng.h"
#include "PCAPNGReader.h"
#include "PCAPNG_m.h"
#include "PCAPRTUDSScheduler.h"


#define extEV (ev.isDisabled()) ? std::cout : std::cout << "[IEEE802154ExtInterface]: "    // switchable debug output

/*
 * Dispatching IEEE802154 Interface
 */
class IEEE802154ExtInterface : public cSimpleModule
{
  protected:
    //has to be redefined to prevent memory leak/protection access with them
    cMessage *rtEvent;                  /* new items received at RTScheduler, for event trigger */
    PCAPRTUDSScheduler *rtScheduler; /* access to real network interface via Scheduler class */
    cMessage *initEvent;  // signals that a pcap File Header Frame has complete arrived in Buffer

    std::map<int, int> interfaceTable;  //interface_id = moduleid
    int interfaces;

    IEEE802154Serializer *serializer;

    // statistics
    int numSent;
    int numRcvd;

    unsigned char recvBuffer[1<<16];
    unsigned int recvPos;
    int numRecvBytes;

  public:
    IEEE802154ExtInterface();
    virtual ~IEEE802154ExtInterface();
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
    void handleEPB(cMessage *msg);
    void handleIDB(cMessage *msg);
    void handleMsgSim(cMessage *msg);

};

#endif /* IEEE802154EXTINTERFACE_H_ */
