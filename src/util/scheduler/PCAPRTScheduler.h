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
// With lots piece of Code from inet3.4/src/int/linklayer/ext/cSocketRTScheduler.h
// ^-> (c) written by
// Copyright (C) 2005 Andras Varga,
//                    Christian Dankbar, Irene Ruengeler, Michael Tuexen
// 2016/2017 modified by Christoph Schwalbe

#ifndef PCAPRTSCHEDULER_H_
#define PCAPRTSCHEDULER_H_

#define WANT_WINSOCK2

#include <platdep/sockets.h>
//#include "inet/common/INETDefs.h"
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

//Defines for fixed Frame chunks
/*
#define global_pcap_frame_size 24
#define local_pcap_frame_size  16
#define ethernet_frame_size    14
#define ip_frame_size          20
#define udp_frame_size          8
#define tcp_frame_size         20
*/

//pcapng
#include "pcapng.h"
#include "PCAPNGReader.h"

//using namespace inet;

/*
 * PCAPRTScheduler = PcapRTScheduler with embedded IEEE 802.15.4 Frame inside PCAP
 * These RTScheduler should schedule Packets with PCAP-Data.
 */
class PCAPRTScheduler : public cRealTimeScheduler
{
  protected:
      int port;

      //Flags
      bool globalPcapReaded;
      bool localPcapReaded;
      bool localPcapPktReaded;
      bool SHBMagicReaded;
      bool IDBReaded;

      const unsigned int MAGIC_NUMBER_SHB    = 0x0A0D0D0A;
      const unsigned int MAGIC_NUMBER_BIG    = 0x1A2B3C4D;
      const unsigned int MAGIC_NUMBER_Little = 0xD4C3B2A1;

      struct pcap_file_header global_pcap_hdr;
      struct pcap_pkthdr local_pcap_pkthdr;
      std::vector <struct pcap_pkthdr> queue_pkthdr; //TODO: queue of shb blocks and data? in ... buffer queue?

      PCAPNGReader *r;
      block_header curr_block;

      cModule *module;
      cMessage *notificationMsg;
      cMessage *initMsg;
      cMessage *waitforBytes;
      cMessage *pktHdrMsg;
      //cMessage *IDBMSGEvent;
      std::vector<cMessage *>IDBMSGEvent;
      std::vector<cMessage *>EPBMSGEvent;

      unsigned char *recvBuffer;  //uint8 *recvBuffer, Buffer is used with call-by-reference, -> use Buffer in other class, //TODO: Ringbuffer
      int recvBufferSize;
      int *numBytesPtr;

      unsigned int nextFramePos;
      unsigned int nextFrameLength;
      unsigned int count;
      unsigned int idb_counter;

      unsigned int arrived;

      timeval baseTime;
      SOCKET listenerSocket;
      SOCKET connSocket;
      int nBytes;

      virtual void setupListener();
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

    void handleBursts();
    void handleFragments();
    void handleFileHdr();
    void handleSHB();
    void handleIDB();
    void handleEPB();
    void handleBlock();

    bool waitForBlock();


    // read 4 Bytes in little Endian
    inline bpf_u_int32 read4Bytes(unsigned char * buf, int from)
    {
            bpf_u_int32 value = 0;

            value = buf[from];
            value = (value & 0xFF) << 8;
            value = (value | buf[from+1]);
            value = (value & 0xFFFF) << 8;
            value = (value | buf[from+2]);
            value = (value & 0xFFFFFF) << 8;
            value = (value | buf[from+3]);
            return value;
    }

    // read 2 Bytes in little Endian
    inline bpf_u_int32 read2Bytes(unsigned char * buf, int from)
    {
        bpf_u_int32 value = 0;

        value = buf[from];
        value = (value & 0xFF) << 8;
        value = (value | buf[from + 1]);
        return value;
    }
};

#endif /* PCAPRTSCHEDULER_H_ */
