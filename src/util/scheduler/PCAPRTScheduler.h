//
// Copyright (C) 2005 Andras Varga,
//                    Christian Dankbar, Irene Ruengeler, Michael Tuexen
// Copyright (C) 2017 Christoph Schwalbe (original PCAP extensions)
// Copyright (C) 2018 Sebastian Boehm (BTU-CS)
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#ifndef PCAPRTSCHEDULER_H_
#define PCAPRTSCHEDULER_H_

#define WANT_WINSOCK2

#include <platdep/sockets.h>
#include "INETDefs.h"

#if OMNETPP_VERSION < 0x500
#include <platdep/timeutil.h>
#else // OMNETPP_VERSION < 0x500
#include <omnetpp/platdep/timeutil.h>
#endif // OMNETPP_VERSION < 0x500
#include <omnetpp.h>

// prevent pcap.h to redefine int8_t,... types on Windows
#include "bsdint.h"
#define HAVE_U_INT8_T
#define HAVE_U_INT16_T
#define HAVE_U_INT32_T
#define HAVE_U_INT64_T
#ifdef HAVE_PCAP
#include <pcap.h>
#endif

#include <vector>
#include "PlainPkt_m.h"
#include "PCAPNG_m.h"
#include "pcapng.h"
#include "PCAPNGReader.h"
#include "Buffer.h"

#define rtEV (ev.isDisabled()) ? std::cout : std::cout << "[PCAPRTScheduler]: "    // switchable debug output

/*
 * This RTScheduler should PCAP Packets.
 */
class PCAPRTScheduler : public cRealTimeScheduler
{
  protected:
      int port;

      //Flags
      bool SHBReaded;
      bool IDBReaded;

      PCAPNGReader *pcapng;
      block_header curr_block;

      cModule *module;

      cMessage *notificationMsg;
      cMessage *waitforBytes;
      cMessage *initMsg;
      std::vector<cMessage *>IDBMSGEvent;
      std::vector<cMessage *>EPBMSGEvent;

      unsigned char *recvBuffer;  //uint8 *recvBuffer, Buffer is used with call-by-reference, -> use Buffer in other class, //TODO: Ringbuffer
      int recvBufferSize;
      int *numBytesPtr;

      unsigned int nextFramePos;
      unsigned int nextFrameLength;

      timeval baseTime;
      SOCKET listenerSocket;
      SOCKET connSocket;
      int nBytes;

      virtual void setupListener();
      virtual void connectSocket();
      virtual bool receiveWithTimeout(long usec);
      virtual int receiveUntil(const timeval& targetTime);

  public:
    PCAPRTScheduler();
    virtual ~PCAPRTScheduler();
    virtual std::string info() const override;

    /*
     * Called at the beginning of a simulation run.
     */
    virtual void startRun() override;
    /**
     * Called at the end of a simulation run.
     */
    virtual void endRun() override;
    /**
     * Recalculates "base time" from current wall clock time.
     */
    virtual void executionResumed() override;
    /**
     * To be called from the module which wishes to receive data from the
     * socket. The method must be called from the module's initialize()
     * function.
     */
    virtual void setInterfaceModule(cModule *module, cMessage *notificationMsg, cMessage *initMsg,
                unsigned char *recvBuffer, int recvBufferSize, int *numBytesPtr);
    /**
     * Returns the first event in the Future Event Set.
     */
    //virtual cEvent *guessNextEvent() override;
    //virtual cEvent *takeNextEvent() override;
    /**
     * Scheduler function -- Store event back for scheduling. it comes from the cScheduler interface.
     */
    //virtual void putBackEvent(cEvent *event) override;

    /**
     * Scheduler function -- it comes from cScheduler interface.
     */
    virtual cMessage *getNextEvent();

    /**
     * Send SHB
     */
    void sendSHB();

    /**
    * Send IDB
    */
    void sendIDB(int linktype, int snaplen);

    /**
     * Send payload with EPB
     */
    void sendEPB(int interface, simtime_t_cref time, Buffer &b);

    /**
     * Send on the currently open connection
     */
    virtual void sendBytes(unsigned char *buf, size_t numBytes);

    /*
     * check if in Buffer are valid IEEE 802.15.4 Packet(s), checks the global pcap hdr
     */
    bool checkPacket();

    /*
     * check in Buffer if the global pcap hdr is present and if Linktype equals Parameter Linktype
     */
    void checkPacket(uint16_t LinkType);

    void handleFragments();
    void handleSHB();
    void handleIDB();
    void handleEPB();
    void handleBlock();

    bool waitForBlock();
};

#endif /* PCAPRTSCHEDULER_H_ */
