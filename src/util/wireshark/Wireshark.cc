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

#include "Wireshark.h"

Define_Module(Wireshark);

void Wireshark::initialize()
{
    if (hasPar("wiresharkDebug"))
        debug = par("wiresharkDebug").boolValue();
    else
        debug = false;

    if (hasPar("datalinkType"))
        datalink = par("datalinkType");
    else
        datalink = DLT_IEEE802_15_4_NOFCS;

    if (hasPar("live"))
        live = par("live").boolValue();
    else
        live = false;

    if (hasPar("file"))
        file = par("file").stringValue();

    connectionOpen = true;

    if (live)
        exec();
    else
        openFile();

    writeGlobalHeader();
}

void Wireshark::close()
{
    pclose(outStream);
}

void Wireshark::transmitPCAP(Buffer buffer, simtime_t_cref time)
{
    writeWiresharkFrame(buffer, time);
}

void Wireshark::writeGlobalHeader()
{
    uint8_t buf[PCAP_HDR_LEN];
    memset((void *)&buf, 0, sizeof(buf));

    Buffer header(buf, sizeof(buf));
    header.writeUint32(PCAP_MAGIC_NUMBER);
    header.writeUint16(2);
    header.writeUint16(4);
    header.writeUint32(0);
    header.writeUint32(0);
    header.writeUint32(PCAP_MAX_PACKET_SIZE);
    header.writeUint32(datalink);

    writeFrame(header);
}

void Wireshark::writeFrameHeader(simtime_t_cref time, uint32_t length)
{
    uint8_t buf[PCAP_FRHDR_LEN];
    memset((void *)&buf, 0, sizeof(buf));

    Buffer header(buf, sizeof(buf));
    header.writeUint32(time.raw() / time.getScale());
    header.writeUint32(time.raw() % time.getScale() / MICROSECONDS);
    header.writeUint32(length);
    header.writeUint32(length);

    writeFrame(header);
}

void Wireshark::writeWiresharkFrame(Buffer frame, simtime_t_cref timestamp)
{
    if (datalink == DLT_IEEE802_15_4_NOFCS) {
        uint32_t frameSize = frame.getPos() - sizeof(uint16_t);
        writeFrameHeader(timestamp, frameSize);
        writeFrame(frame, frameSize);
    } else {
        writeFrameHeader(timestamp, (uint32_t)frame.getPos());
        writeFrame(frame);
    }
}

void Wireshark::writeFrame(Buffer frame, size_t length)
{
    const uint8_t* buf = frame._getBuf();
    for (size_t i=0; i<length; i++) {
        write((unsigned char)buf[i]);
    }
}

void Wireshark::writeFrame(Buffer frame)
{
    const uint8_t* buf = frame._getBuf();
    for (size_t i=0; i<frame.getPos(); i++) {
        write((unsigned char)buf[i]);
    }
}

void Wireshark::write(unsigned char byte)
{
    fputc(byte, outStream);
    fflush(outStream);
}

void Wireshark::exec()
{
    if(!(outStream = popen(cmd, "w")))
        throw cRuntimeError("Could not open Wireshark!");
}

void Wireshark::openFile()
{
    if(!(outStream = fopen(file, "w")))
        throw cRuntimeError("Could not open File!");
}
