//
//
// Copyright (C) 2016 Sebastian Boehm (BTU-CS)
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

#ifndef WIRESHARK_H_
#define WIRESHARK_H_

#include <omnetpp.h>
#include <string>
#include <iostream>
#include <cstdio>
#include <memory>
#include <Buffer.h>
#include <pcap/pcapng.h>

enum PcapConst {
    PCAP_MAX_PACKET_SIZE    = 128,
    PCAP_MAGIC_NUMBER       = 0xa1b2c3d4,
    PCAP_HDR_LEN            = 24,
    PCAP_FRHDR_LEN          = 16,
    MICROSECONDS            = 1000000
};

#define wEV (ev.isDisabled()||!debug) ? std::cout : std::cout << "[Wireshark]: "    // switchable debug output

/**
 * Inputs frames to Wireshark with simple PCAP-Header
 */
class Wireshark : public cSimpleModule
{
    protected:
        /** @brief Debug output switch for the Wireshark module */
        bool debug = true;
        bool connectionOpen = false;
        bool live = false;
        const char* cmd = "wireshark -k -i -";
        const char* file = "test.pcap";
        FILE *outStream;
        uint32_t datalink;

        virtual void initialize();

    public:
        Wireshark() {}
        virtual ~Wireshark() {}
        virtual void close();
        virtual void transmitPCAP(Buffer buffer, simtime_t_cref time);
        virtual void writeGlobalHeader();
        virtual void writeFrameHeader(simtime_t_cref time, uint32_t length);
        virtual void writeWiresharkFrame(Buffer frame, simtime_t_cref timestamp);
        virtual void writeFrame(Buffer frame);
        virtual void writeFrame(Buffer frame, size_t length);
        virtual void write(const uint8_t);
        bool isOpen() const { return connectionOpen; }

    private:
        virtual void exec();
        virtual void openFile();
};

#endif /* WIRESHARK_H_ */
