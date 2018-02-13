/*
 * PCAPNGReader.h
 *
 *  Created on: 2017
 *      Author: Christoph Schwalbe
 *
 *      This class is in development and only for purpose to analyse Bytes (pcapng-FileFormat) received via cSocketRTScheduler.
 *      Normally a PCAPNGReader would read all Bytes in a static way. A File will be read and this has an amount of Bytes (size length can be determined).
 *      But in this Situation we have a dynamic Byte stream, because this class is used in that case. The File size can't be determined at the beginning,
 *      and maybe only for a Section. Section is {SHB| IDB | ... |} and the section size will be the block_length of all together until next SHB beginns.
 *        Otherwise there is no really easy way to determine how long a PCAPNG Stream will be.
 */

#ifndef PCAPNGREADER_H_
#define PCAPNGREADER_H_

#pragma once

#include "pcapng.h"
#include <iostream>
#include <iomanip>        //std::stringstream
#include <string>
#include "misc.h"

#include <netinet/in.h>  //ntohs, ntohl
#include <cstring>      //memcpy
#include <IPv4Address.h>
#include <IPv6Address.h>
#include <MACAddress.h>
#include "MACAddressExt.h"

//for file reading
#include <stdio.h>
#include <stdexcept>
#include <map>

// EPB Option Flags Word
enum FlagsIO              //Bits 0-1
{
  Information_not_available = 0,
  inbound = 1,
  outbound = 2
};
enum ReceptionType         //Bits 2-4
{
    not_specified = 0,
    unicast = 1,
    multicast = 2,
    broadcast = 3,
    promiscuous = 4
};
// FCS length = 0000 -> Information_not_available; Bits 5-8
// LinkLayerDependentErrors -> Stellen beachten -> wenn gesetzt -> Fehler; Bits 16 - 31


enum BlockType
{
    SectionHeader = BT_SHB,
    InterfaceDescriptionHeader = BT_IDB,
    EnhancedPacketHeader = BT_EPB,
    SimplePacketBlick = BT_SPB,
    NameResolutionBlock = BT_NRB,
    InterfaceStatisticsBlock = BT_ISB,
    Reserved = BT_RES,
    Obsolet = BT_PB,
    Custom = BT_CB,
    Custom2 = BT_CB2
};

typedef section_header_block shb;

using namespace std;

class MACAddressExt;
class MACAddress;

class PCAPNGReader
{
private:
    //Experiment of collecting information from one pcapng section { SHB | IDB | [EPB] | ... | }
    struct section{
        uint32_t sectionSize;
        uint16_t linkType;
        uint32_t packetBlockTypes[100]; //better be std::vector ...
    };

    unsigned char* buffer;
    size_t bufferSize;
    size_t bufferPos;
    FILE *file;

    size_t blockSize;
    bool isBlockOpen;
    block_header *currentBlock;
    block_trailer *currentTrailer;
    block_cursor *currentCursor;

    section_header_block *shb;

    option_header* option;  //TODO: as vector, queue, list or sth else? save all Options from all blocks somewhere

    //std::string Hardware_info;
    //std::string OS_info;
    //std::string UserApplication_info;
    uint32_t hw_info, os_info, userapplication_info;
    unsigned char hw[256];           //UTF-8 Converter: https://sites.google.com/site/nathanlexwww/tools/utf8-convert

    bool isSectionOpen;
    size_t sectionSize;
    fpos_t sectionStart;

    const unsigned long int SECTION_LENGTH_UNKOWN = 18446744073709551615UL;  // is -1 is 0xFFFF FFFF FFFF FFFF
    bool isSectionIndetermined;            // Section is indetermined, section_length == -1 (0xFFFF FFFF FFFF FFFF)
    bool hasOptions;
    bool hasEndOption;
    bool hasSectionEnd;
    bool magicReaded;

    size_t numInterfaces;                   //keep

    std::map<size_t, fpos_t> interfacePos;  //delete?

    //### IDB ###
    interface_description_block *idb;
    bool isIDBOpen;
    unsigned char name[256];            //if_name
    unsigned char description[256];      //if_description
    unsigned char filter[256];           //if_filter  , Traffic Filter in BPF Format
    unsigned char os[24];
    unsigned char ipv4addr[8];
    unsigned char ipv6addr[17];
    unsigned char macaddr[12];
    unsigned char euiaddr[16];
    unsigned char speed[8];
    uint8_t tsresol;
    unsigned char tzone[4];
    uint8_t fcslen;
    unsigned char tsoffset[8];



    IPv4Address *ip;
    IPv6Address *ipv6;
    MACAddress *mac;
    MACAddressExt *macext;             //forward declaration error, cycle error, reorder File structure to solve this
    //### IDB ###

    //### EPB ###
    enhanced_packet_block *epb;
    unsigned char packet_data[128];
    bool isEPBOpen;
    uint32_t flags;
    unsigned char hash[100]; //how long should it be?
    unsigned char dropcount[8];
    unsigned int packetBegin;
    //### EPB ###


    //TODO: handle we have more than one SHB .. more sections
    //TODO: handle we have a simple Packet Block with more than one IDB, it cannot be:
    /*
     * "A Simple Packet Block cannot be present in a Section that has more than one interface because of the impossibility
     *  to refer to the correct one (it does not contain any Interface ID field)."
     *  source: http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html#sectionpbs or https://pcapng.github.io/pcapng/#rfc.section.4.4
     * */

    //### SPB ###//
    bool isSPBOpen;
    simple_packet_block *spb;

    std::stringstream stream;
    std::string result;

public:
    PCAPNGReader(void * setBuffer, size_t setBufferSize);
    virtual ~PCAPNGReader();

    bool isSectionEnd();
    uint32_t getBlockLength();
    bool hasBlockOpen();
    bool getMagicReaded();
    uint16_t getLinkType();
    block_header getCurrentBlockHeader();
    enhanced_packet_block getEPB();
    void getPacket(unsigned char *buffer);
    unsigned int getPacketBegin();
    MACAddress* getMAC();
    unsigned char* getEUIAddr();
    uint16_t skipPaddingBytes(uint16_t adjustedBlockLength);
    void printHexUTF8(unsigned char *b, uint16_t len);


    void openFile(const char *filename);
    void closeFile();

    void peekBlock(block_header &block, int peekPos);

    void openBlock();
    void closeBlock();

    void openSectionHeader();
    void closeSection();

    void openSHBOptionBlock();
    void closeOption();

    void openInterfaceDescription();
    void closeInterface();

    void openIDBOptionBlock();

    void openEnhancedPacketBlock();
    void closeEnhancedPacket();

    void openEPBOptionBlock();

    void openSimplePacketBlock();
    void closeSimplePacket();

    /* see core sim pcapngwriter
    void addInterfaceDescriptionHeader(uint16_t linktype, uint32_t snaplen);
    void changeInterfaceDescriptionHeader(size_t interfaceId, uint16_t linktype, uint32_t snaplen);
    void addEnhancedPacketHeader(uint32_t interfaceId, uint64_t timestamp, uint32_t caplen, uint32_t len);
    void openSection(std::string hardware, std::string os, std::string application);
    size_t addInterface(std::string name, std::string description, uint16_t linktype, uint32_t snaplen, uint8_t tsresol, uint64_t speed);
    void addEnhancedPacket(uint32_t interfaceId, bool sender, uint64_t timestamp, uint32_t len, uint32_t caplen, void* data, bool bitError);
*/
};




#endif /* PCAPNGREADER_H_ */
