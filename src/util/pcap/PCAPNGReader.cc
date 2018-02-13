/*
 * PCAPNGReader.cc
 *
 *  Created on: Feb 15, 2017
 *      Author: omnet
 */

#include "PCAPNGReader.h"

/*
 * How it works:
 *
 * Block length + Padding (Option(s) length) = real Block length
 * Next Block
 *
 *
 */


PCAPNGReader::PCAPNGReader(void * setBuffer, size_t setBufferSize)
{
    buffer = static_cast<unsigned char*>(setBuffer);
    bufferSize = setBufferSize;                                 //Err after writing over bufferSize, TODO: Ringbuffer
    bufferPos = 0;
    blockSize = 0;
    isBlockOpen = false;
    file = nullptr;

    isSectionOpen = false;
    sectionSize = 0;
    hasSectionEnd = false;
    isSectionIndetermined = false;

    hasOptions = false;
    hasEndOption = false;
    numInterfaces = 0;

    currentBlock = nullptr;
    currentTrailer = nullptr;
    currentCursor = nullptr;
    shb = nullptr;
    magicReaded = false;

    //Hardware_info = nullptr;
    //OS_info = nullptr;
    //UserApplication_info = nullptr;
    hw_info = os_info = userapplication_info = 0;

    isIDBOpen = false;
    idb = nullptr;
    /*...*/
    ip = nullptr;
    ipv6 = nullptr;
    mac = nullptr;
    //macext = nullptr;

    isEPBOpen = false;
    epb = nullptr;

    isSPBOpen = false;
    spb = nullptr;
}

PCAPNGReader::~PCAPNGReader()
{
  //delete all frree
}

void PCAPNGReader::peekBlock(block_header &block, int peekPos)
{
    block.block_type = read4BytesNtohl(buffer, peekPos);
    block.total_length = read4BytesNtohl(buffer, peekPos+4);
}

void PCAPNGReader::openBlock()
{
    if (isBlockOpen) {
        std::cout << "already is a block open, block type: " << currentBlock->block_type << std::endl;
        throw std::invalid_argument("there is already an open block");
    }

    currentBlock = reinterpret_cast<block_header*>(buffer + bufferPos);
    currentBlock->block_type = read4BytesNtohl(buffer, bufferPos);
    currentBlock->total_length = read4BytesNtohl(buffer, bufferPos+4);

    std::cout << "== open block, block type: " << std::hex << currentBlock->block_type << std::dec << " ==" << std::endl;

    bufferPos += sizeof(block_header);

    hasOptions = false;
    isBlockOpen = true;
    hasEndOption = false;
}

void PCAPNGReader::closeBlock()
{
    currentTrailer = reinterpret_cast<block_trailer*>(buffer + bufferPos);
    currentTrailer->total_length = currentBlock->total_length;     //cmp this later with last 4 Bytes
    bufferPos += sizeof(block_trailer);

    std::cout << "bufferPos: " << bufferPos << std::endl;

    if (currentTrailer->total_length != this->currentBlock->total_length)
    {
      std::cerr << "Length of Block mismatches. First length: " << currentBlock->total_length << " Second length: " << currentTrailer->total_length << std::endl;
    }

    //sectionSize += bufferPos;
    if (shb->section_length == SECTION_LENGTH_UNKOWN){
        std::cout << "bufferPos: " << bufferPos << " of unknown sectionlength (-1)" << std::endl;
    } else {
        std::cout << "bufferPos: " << bufferPos << " of sectionlength: " << shb->section_length << std::endl;
    }


    //bufferPos == shb->section_length && isSectionIndetermined == false
    if ( bufferPos == shb->section_length ){
        hasSectionEnd = true;
        //TODO: FIXME: für dynamische Section mit keiner Angabe der Länge 0xFFFFFFFFFFFFFFFF == -1 bestimme aus: currentTrailer->total_length != this->currentBlock->total_length
        //if(this->isSectionIndetermined) if is next SHB
    }
    else {
        hasEndOption = false;
    }

    isBlockOpen = false;
    std::cout << "== closed block, block type " << this->currentBlock->block_type << " ==" << std::endl;
}

void PCAPNGReader::openSectionHeader()
{
    if(!currentBlock->block_type){
        throw std::invalid_argument("no Block Header have been currently processed, block_type is missing");
    }
    // DEBUG - Information
    //std::cout << "Blocktype: " << currentBlock->block_type << std::endl;
    //std::cout << "bufferPos: " << bufferPos << std::endl;
    //std::cout << "content: " << read4BytesNtohl(buffer, bufferPos) << std::endl;

    if (currentBlock->block_type == SectionHeader)
    {
        std::cout << "open SHB" << std::endl;
        shb = reinterpret_cast<section_header_block*>(buffer + bufferPos);
        shb->byte_order_magic = read4Bytes(buffer, bufferPos);


        uint32_t part1 = 0;
        uint32_t part2 = 0;

        switch (shb->byte_order_magic)
        {
            case BYTE_ORDER_MAGIC:
                  std::cout << "Big-Endian Byte-Order" << std::endl;
                  shb->major_version = read2Bytes(buffer, bufferPos+4);   //untestet
                  shb->minor_version = read2Bytes(buffer, bufferPos+6);   //untestet
                break;
            case BYTE_ORDER_MAGIC_LITTLE: std::cout << "Little-Endian Byte-Order" << std::endl;
                  //std::cout << "major: " << read2BytesNtohs(buffer, bufferPos+4) << std::endl;   //ntohs(read2Bytes(buffer, bufferPos+4));
                  shb->major_version = read2BytesNtohs(buffer, bufferPos + 4);
                  shb->minor_version = read2BytesNtohs(buffer, bufferPos + 6);

                  part1 = read4BytesNtohl(buffer, bufferPos + 8); //FIXME: 64 bit ...
                  part2 = read4BytesNtohl(buffer, bufferPos + 12);

                  std::cout << part1 << std::endl;
                  std::cout << part2 << std::endl;

                  //section length == -1 == 0xFFFF FFFF FFFF FFFF
                  if (part1 == part2){
                      // section length is "-1" aka: Unknown length of Section. Handle: read block after block
                      // easy peace of code, only 1 cmp, no shift, no add, no or
                      // setFlag
                      isSectionIndetermined = true;
                      shb->section_length = static_cast<uint64_t>(-1);
                      //std::cout << shb->section_length;
                      //printf("%lu", shb->section_length);
                      //shb->section_length = 0xFFFFFFFFFFFFFFFF;
                  } else {
                      // there is a section length, all total block length inclusive this block summa summarum should be equal to this section length,
                      // if not: error/brocken block SHB/section is changed
                      shb->section_length = ((uint64_t)part1 << 32) | part2;
                      // or read only part1
                  }


                  //shb->section_length = static_cast<uint64_t>(-1); //-1 sorgt für einen Sonderfall
                  //if (shb->section_length == static_cast<uint64_t>(-1)) skipSection, see Standard

                break;
            case BIG_SWAPPED: std::cout << "Big-Endian Swapped Byte-Order" << std::endl;
                break;
            case LITTLE_SWAPPED: std::cout << "Little-Endian Swapped Byte-Order" << std::endl;
                break;
            default: {
                std::cout << "Unkown Endian or SHB Byte-Order Magic was not successfully readed: " << shb->byte_order_magic << std::endl;
            }
        }

        bufferPos += sizeof(section_header_block);
        //std::cout << "bufferPos: " << bufferPos << std::endl;
        //std::cout << "content: " << read4BytesNtohl(buffer, bufferPos) << std::endl;
        std::cout << "Section Length: " << (uint64_t)shb->section_length << std::endl;

        //currentCursor->block_type = this->currentBlock->block_type;
        //currentCursor->data_remaining = shb->section_length - bufferPos;
        //currentCursor->data = static_cast<u_char*>(buffer[bufferPos]);
        std::cout << "version: " << shb->major_version << std::endl;

        //verify supported Pcapng Version
        if (!(shb->major_version == PCAP_NG_VERSION_MAJOR)){
            std::cout << "not supported major Version: " << shb->major_version << std::endl;
            exit(-1);
        }
        if (!(shb->minor_version == PCAP_NG_VERSION_MINOR)){
            std::cout << "not supported minor Version: " << shb->minor_version << std::endl;
            exit(-1);
        }
    }

    isSectionOpen = true;

    //OffsetPos = Block Total Length - SHB length without Options, if (OffsetPos > 0) there are Bytes for Options, or SHB is broken
    if (currentBlock->total_length - 28 > 0){
        std::cout << "SHB has Options." << std::endl;
        hasOptions = true;
        openSHBOptionBlock();
        //TODO: FIXME: What if the SHB is broken?
    }

    closeSection();        //this should actually closed if the SHB is really finished and the next SHB begins, or section_length achievwd
    closeBlock();
}

void PCAPNGReader::closeSection()
{
    if (!isSectionOpen) {
        throw std::invalid_argument("there is no open section");
    }
    isSectionOpen = false;
}

uint32_t PCAPNGReader::getBlockLength()
{
   return currentBlock->total_length;
}

block_header PCAPNGReader::getCurrentBlockHeader()
{
   return *this->currentBlock;
}

bool PCAPNGReader::isSectionEnd(){
    return hasSectionEnd;
}


void PCAPNGReader::openSHBOptionBlock()
{
    if (!hasOptions) throw std::invalid_argument("there are no Options.");

    std::cout << "open SHB OptionBlock" << std::endl;

    option = reinterpret_cast<option_header*>(buffer + bufferPos);
    option->option_code = read2BytesNtohs(buffer, bufferPos);
    option->option_length = read2BytesNtohs(buffer, bufferPos+2);
    bufferPos += sizeof(option_header);

    std::cout << "option code: " << option->option_code << std::endl;
    std::cout << "option length: " << option->option_length << std::endl;

    // UTF-8 conversion to string
    switch(option->option_code){
        case SEC_HARDWARE:
            memcpy(hw, buffer + bufferPos, (size_t)option->option_length);
            this->printHexUTF8(hw, option->option_length);
            //hw_info = read4Bytes(buffer, bufferPos);
            //std::cout << "hw info: " << hw_info << std::endl;
            //FIXME: convert to UTF-8 String
            break;
        case SEC_OS:
            //FIXME: convert to UTF-8 String
            memcpy(hw, buffer + bufferPos, (size_t)option->option_length);
            printHexUTF8(hw, option->option_length);
            break;
        case SEC_USERAPPL:
            //FIXME: convert to UTF-8 String
            memcpy(hw, buffer + bufferPos, (size_t)option->option_length);
            printHexUTF8(hw, option->option_length);
            break;
        case OPT_ENDOFOPT: /* end of options */
            std::cout << "End of option, length: " << option->option_length << std::endl; //length should be 0
            break;

        case OPT_COMMENT:
            memcpy(hw, buffer + bufferPos, (size_t)option->option_length); //FIXME: convert to UTF-8 String
            std::cout << "comment " << std::endl;
            printHexUTF8(hw, option->option_length);
            break;

        default: {
            std::cout << "these is not a valid option" << std::endl;
        }
    }

    std::cout << "bufferPos nach Options value: " << bufferPos << std::endl;

    // Pad Bytes Problem option->option_length + x Padding Bytes
    bufferPos+= option->option_length + skipPaddingBytes(option->option_length);
    std::cout << "bufferPos: " << bufferPos << std::endl;
    std::cout << "content: " << read4BytesNtohl(buffer, bufferPos) << std::endl;

    //Is there another Option? or EndOpt?
    option = reinterpret_cast<option_header*>(buffer + bufferPos);
    option->option_code = read2BytesNtohs(buffer, bufferPos);
    option->option_length = read2BytesNtohs(buffer, bufferPos + 2);

    if (option->option_code == OPT_ENDOFOPT && option->option_length == 0){
        //nothing to do options are finished
        this->hasEndOption = true;
        this->closeOption();
    } else {
        std::cout << "has option: " << hasOptions << " und lade weiteren Block." << std::endl;
        openSHBOptionBlock();       //Achtung statische Loesung! -> dynamisch Lsg, setze flag, check Bytes and read again
        //kehre zum Aufrufer zurück und warte auf sein Signal: neue Bytes bzw. es sind noch genügend Bytes übrig.
        //  Was wäre dann genügend Bytes?
    }

}

void PCAPNGReader::closeOption()
{
    if (!hasEndOption){
        throw std::invalid_argument("Options haven't finished yet.");
    }
    bufferPos+= 4; //{Option code == opt_endofopt + Option Length == 0} = 4 Byte
}

// call openBlock() before
void PCAPNGReader::openInterfaceDescription()
{
    if(currentBlock->block_type != BT_IDB){
       throw std::invalid_argument("that Block is not an Interface Description Block");
    }  // check block_type == IDB ?
    isIDBOpen = true;

    std::cout << "open IDB" << std::endl;
    std::cout << "bufferPos: " << bufferPos << std::endl;
    idb = new interface_description_block;                           //reinterpret_cast
    //idb = static_cast<interface_description_block*>(idb);
    idb->linktype = read2BytesNtohs(buffer, bufferPos);
    //idb->reserved =
    idb->snaplen = read4BytesNtohl(buffer, bufferPos+4);

    bufferPos += sizeof(interface_description_block);
    std::cout << "bufferPos: " << bufferPos << std::endl;
    //Options
    //OffsetPos = Block Total Length - IDB length without Options, if (OffsetPos > 0) there are Bytes for Options, or broken SHB
    if (currentBlock->total_length - 20 > 0) {
        std::cout << "IDB has Options." << std::endl;
        hasOptions = true;
        openIDBOptionBlock();
    }

    closeInterface();
    closeBlock();
}

void PCAPNGReader::closeInterface()
{
    if (!isIDBOpen) {
      throw std::invalid_argument("there is no open IDB");
    }
    isIDBOpen = false;
}

void PCAPNGReader::openIDBOptionBlock()
{
    if (!hasOptions) throw std::invalid_argument("there are no Options.");

    std::cout << "open IDB OptionBlock" << std::endl;

    option = reinterpret_cast<option_header*>(buffer + bufferPos);
    option->option_code = read2BytesNtohs(buffer, bufferPos);
    option->option_length = read2BytesNtohs(buffer, bufferPos+2);
    bufferPos += sizeof(option_header);

    std::cout << "option code: " << option->option_code << std::endl;
    std::cout << "option länge: " << option->option_length << std::endl;

    // UTF-8 conversion to string missing, take care about Byte-Order with Address also
    switch(option->option_code){
        case IF_NAME:
            memcpy(name, buffer + bufferPos, (size_t)option->option_length);
            //name = read4Bytes(buffer, bufferPos);
            std::cout << "if_name: " << name << std::endl;
            //FIXME: convert to UTF-8 String
            break;
        case IF_DESCRIPTION:
            //FIXME: convert to UTF-8 String
            memcpy(description, buffer + bufferPos, (size_t)option->option_length);
            std::cout << "description: " << description << std::endl;
            break;
        case IF_FILTER:
            //FIXME: convert to UTF-8 String
            memcpy(filter, buffer + bufferPos, (size_t) option->option_length);
            break;
        case IF_OS:
            //FIXME: convert to UTF-8 String
            memcpy(os, buffer + bufferPos, (size_t) option->option_length);
            break;
        case IF_IPV4ADDR:
            memcpy(ipv4addr, buffer + bufferPos, (size_t) sizeof(ipv4addr));
            ip = new IPv4Address(ipv4addr[0],ipv4addr[1],ipv4addr[2],ipv4addr[3]);  //prototypisch

            break;
        case IF_IPV6ADDR: memcpy(ipv6addr, buffer + bufferPos, (size_t) sizeof(ipv6addr)); //prototypisch, add stuff
                         //use 4 uint32_t or uint64_t twice
                         //ipv6 = new inet::IPv6Address();
            break;
        case IF_MACADDR:  memcpy(macaddr, buffer + bufferPos, (size_t) sizeof(macaddr));
                          mac = new MACAddress((char*)macaddr);                            //prototypisch
            break;
        case IF_EUIADDR:  memcpy(euiaddr, buffer + bufferPos, (size_t) 8);
                          std::cout << "euiaddr found, do getEUIAddr()" << std::endl;

                          uint32_t test,test2;
                          test = read4Bytes(buffer, bufferPos);
                          test2 = read4Bytes(buffer, bufferPos+4);
                          //std::cout << std::hex << test << " " << test2 << std::endl;
                          //std::cout << std::dec << std::endl;


                          stream << std::hex << test << test2;
                          result = stream.str();
                          //std::cout << result << std::endl;
                          if (result.length() < 16){ // if first value is 00 it will be shiftet out and not shown in hexstream so add 00 if
                             result = "00" + result;
                          }
                          memcpy(euiaddr, result.c_str(), (size_t) 16);
                          for(unsigned int i=0; i < 16; i+=2){
                              std::cout << euiaddr[i] << euiaddr[i + 1] << " ";
                          }

                          //macext->setAddress(euiaddr);
                          //macext = macext->MACAddressExt((char*)euiaddr);  // with forward error correction didn't work (in same folder, check include path)
                          //macext = new MACAddressExt((char*)euiaddr);                      //prototypisch, add MACAddressExt class or use inet > 2.6 + OMNEt...
            break;
        case IF_SPEED:  memcpy(speed, buffer + bufferPos, (size_t) sizeof(speed));
            break;
        case IF_TSRESOL:  tsresol = buffer[bufferPos];
            break;
        case IF_TZONE:  memcpy(this->tzone, buffer + bufferPos, (size_t) sizeof(tzone));
            break;
        case IF_FCSLEN:   this->fcslen = buffer[bufferPos];
            break;
        case IF_TSOFFSET: memcpy(this->tsoffset, buffer + bufferPos, (size_t) sizeof(tsoffset));
            break;

        case OPT_ENDOFOPT: /* end of options */
            std::cout << "End of option länge: " << option->option_length << std::endl; //length sollte 0 sein
            break;
        case OPT_COMMENT:
            memcpy(hw, buffer + bufferPos, (size_t)option->option_length); //FIXME: convert to UTF-8 String
            std::cout << "comment " << hw << std::endl;
            break;

        default: {
            std::cout << "these is not a valid option" << std::endl;
        }
    }

    std::cout << "bufferPos nach Options value: " << bufferPos << std::endl;

    // Pad Bytes Problem option->option_length + x Padding Bytes
    bufferPos+= option->option_length + skipPaddingBytes(option->option_length);
    std::cout << "bufferPos: " << bufferPos << std::endl;
    std::cout << "content: " << read4BytesNtohl(buffer, bufferPos) << std::endl;

    //Is there another Option? or EndOpt?
    option = reinterpret_cast<option_header*>(buffer + bufferPos);
    option->option_code = read2BytesNtohs(buffer, bufferPos);
    option->option_length = read2BytesNtohs(buffer, bufferPos + 2);

    if (option->option_code == OPT_ENDOFOPT && option->option_length == 0){
        //nothing to do options are finished
        this->hasEndOption = true;
        closeOption();
    } else {
        std::cout << "has option: " << hasOptions << " und lade weiteren Block." << std::endl;
        openIDBOptionBlock();       //Achtung statische Loesung! -> dynamisch Lsg, setze flag, check Bytes and read again
        //kehre zum Aufrufer zurück und warte auf sein Signal: neue Bytes bzw. es sind noch genügend Bytes übrig.
        //  Was wäre dann genügend Bytes?
    }
}

void PCAPNGReader::openEnhancedPacketBlock()
{
    if(currentBlock->block_type != BT_EPB){
       throw std::invalid_argument("that Block is not an Enhanced Packet Block");
    }
    isEPBOpen = true;

    std::cout << "open EPB" << std::endl;
    epb = reinterpret_cast<enhanced_packet_block*>(buffer + bufferPos);
    epb->interface_id = read4BytesNtohl(buffer, bufferPos);
    epb->timestamp_high = read4BytesNtohl(buffer, bufferPos+4);
    epb->timestamp_low = read4BytesNtohl(buffer, bufferPos+8);
    epb->caplen = read4BytesNtohl(buffer, bufferPos+12);     // Captured Packet Length
    epb->len = read4BytesNtohl(buffer, bufferPos+16);         // Original Packet Length
    std::cout << "bufferPos: " << bufferPos << std::endl;
    std::cout << "size of epb: " << currentBlock->total_length << std::endl;      // sizeof(enhanced_packet_block);
    std::cout << "readed caplen: " << epb->caplen << std::endl;
    bufferPos += sizeof(enhanced_packet_block);
    std::cout << "bufferPos after Packet readed: " << bufferPos << std::endl;
    packetBegin = bufferPos;
    std::cout << "i am cpy now EPB Packet Data" << std::endl;
    memcpy(packet_data, buffer + bufferPos, (size_t)epb->caplen);

    //std::cout << "bufferPos before add epb_caplen and paddBytes: " << bufferPos << " caplen: " << epb->caplen << " padBytes: " << skipPaddingBytes(epb->caplen) << std::endl;
    bufferPos += epb->caplen + skipPaddingBytes(epb->caplen);
    //bufferPos += epb->caplen;
    //OffsetPos = Block Total Length - EPB length without Options, if (OffsetPos > 0) there are Bytes for Options, or broken Block err in section
    if (currentBlock->total_length - 32 - epb->caplen - skipPaddingBytes(epb->caplen) > 0) {
        std::cout << "EPB has Options." << std::endl;
        hasOptions = true;
        openEPBOptionBlock();
        //TODO: FIXME: What if the Block is broken? ignore it...
    }

    closeEnhancedPacket();
    closeBlock();
}

void PCAPNGReader::openEPBOptionBlock()
{
    if (!hasOptions)
        throw std::invalid_argument("there are no Options.");

    std::cout << "open EPB OptionBlock" << std::endl;

    option = reinterpret_cast<option_header*>(buffer + bufferPos);
    option->option_code = read2BytesNtohs(buffer, bufferPos);
    option->option_length = read2BytesNtohs(buffer, bufferPos + 2);
    bufferPos += sizeof(option_header);

    std::cout << "option code: " << option->option_code << std::endl;
    std::cout << "option länge: " << option->option_length << std::endl;

    switch (option->option_code) {
        case EP_FLAGS:
            flags = read4BytesNtohl(buffer, bufferPos);
            break;
        case EP_HASH:
            memcpy(hash, buffer + bufferPos, (size_t) option->option_length);
            break;
        case EP_DROPCOUNT:
            memcpy(dropcount, buffer + bufferPos, (size_t) option->option_length);
            break;
        case OPT_ENDOFOPT: /* end of options */
            std::cout << "End of option länge: " << option->option_length << std::endl; //length sollte 0 sein
            break;

        case OPT_COMMENT:
            memcpy(hw, buffer + bufferPos, (size_t) option->option_length); //FIXME: convert to UTF-8 String
            std::cout << "comment " << std::endl;
            break;

        default: {
            std::cout << "these is not a valid option" << std::endl;
        }
    }

    std::cout << "bufferPos nach Options value: " << bufferPos << std::endl;

    // Pad Bytes Problem option->option_length + x Padding Bytes
    bufferPos += option->option_length + skipPaddingBytes(option->option_length);
    std::cout << "bufferPos: " << bufferPos << std::endl;
    std::cout << "content: " << read4BytesNtohl(buffer, bufferPos) << std::endl;

    //Is there another Option? or EndOpt?
    option = reinterpret_cast<option_header*>(buffer + bufferPos);
    option->option_code = read2BytesNtohs(buffer, bufferPos);
    option->option_length = read2BytesNtohs(buffer, bufferPos + 2);

    if (option->option_code == OPT_ENDOFOPT && option->option_length == 0) {
        //nothing to do options are finished
        this->hasEndOption = true;
        this->closeOption();
    }
    else {
        std::cout << "has option: " << hasOptions << " und lade weiteren Block." << std::endl;
        openEPBOptionBlock();       //Achtung statische Loesung! -> dynamisch Lsg, setze flag, check Bytes and read again
        //kehre zum Aufrufer zurück und warte auf sein Signal: neue Bytes bzw. es sind noch genügend Bytes übrig.
        //  Was wäre dann genügend Bytes?
    }
}

void PCAPNGReader::closeEnhancedPacket()
{
    if (!isEPBOpen) {
          throw std::invalid_argument("there is no open EPB");
    }
    isEPBOpen = false;
}


void PCAPNGReader::openSimplePacketBlock(){
    if (currentBlock->block_type != BT_SPB) {
        throw std::invalid_argument("that Block is not an Simple Packet Block");
    }
    isSPBOpen = true;

    std::cout << "open SPB" << std::endl;
    spb = reinterpret_cast<simple_packet_block*>(buffer + bufferPos);
    spb->len = read4BytesNtohl(buffer, bufferPos);

    std::cout << "bufferPos: " << bufferPos << std::endl;
    bufferPos += sizeof(simple_packet_block);
    std::cout << "bufferPos: " << bufferPos << std::endl;
    std::cout << "i am cpy now SPB Packet Data" << std::endl;
    memcpy(packet_data, buffer + bufferPos, (size_t) spb->len);  //reuse of packet_data, used by EPB !

    bufferPos += spb->len + skipPaddingBytes(spb->len);

    //SPB has no Options
    hasOptions = false;

    //TODO: FIXME: What if the Block is broken? ignore it...

    closeSimplePacket();
    closeBlock();
}

void PCAPNGReader::closeSimplePacket()
{
    if (!isSPBOpen) {
        throw std::invalid_argument("there is no open SPB");
    }
    isSPBOpen = false;
}

MACAddress* PCAPNGReader::getMAC()
{
  return mac;
}

unsigned char* PCAPNGReader::getEUIAddr()
{
    return this->euiaddr;
}

//from ntar lib, ntartest.c
uint16_t PCAPNGReader::skipPaddingBytes(uint16_t adjustedBlockLength)
{
    switch (adjustedBlockLength % 4) {
        case 0:
            return 0;  // no pad bytes
            break;
        case 1:
            return 3;  // add there pad bytes
            break;
        case 2:
            return 2;  // add two pad bytes
            break;
        case 3:
            return 1;  // add one pad bytes
            break;
        default:
            std::cout << "+++ Unexpected remainder: " << (adjustedBlockLength % 4) << std::endl;
            return -1;
            break;
    }
}

//FIXME: convert to real UTF-8 this is only Test, no more Byte interpretation >127 no catch and throw away non printable chars ... 1 Byte UTF-8, 2 Byte UTF-8 ...
void PCAPNGReader::printHexUTF8(unsigned char *b, uint16_t len){
    for (unsigned int i = 0; i < len; i++) {
        std::cout << std::hex << b[i] << "";
    }
    std::cout << std::dec << std::endl;
}

bool PCAPNGReader::hasBlockOpen()
{
    return isBlockOpen;
}

bool PCAPNGReader::getMagicReaded()
{
    return magicReaded;
}

/*
 *todo sicheres umspeichern
 * void PCAPNGReader::setEPB(enhanced_packet_block epb){
 *   this.epb =
 * }
 * */

enhanced_packet_block PCAPNGReader::getEPB()
{
    enhanced_packet_block tmp;
    tmp = *epb;

    return tmp;
}

/* dest-buffer where should Packet stored, length should be epb->caplen, the length
 * "return" value is EPB Packet Data stored in EPB, after opend an EPB Block
 */
void PCAPNGReader::getPacket(unsigned char *buffer)
{
   assert(epb != nullptr);
   assert(epb->caplen > 0);
   memcpy(buffer, packet_data, (size_t)epb->caplen);
}

unsigned int PCAPNGReader::getPacketBegin()
{
    return packetBegin;
}

// return linktype, after idb is readed
uint16_t PCAPNGReader::getLinkType()
{
    assert(idb != nullptr);
    return idb->linktype;
}

// inspiration und quelle: https://opensource.apple.com/source/libpcap/libpcap-67/libpcap/sf-pcap-ng.c.auto.html
/* https://opensource.apple.com/source/libpcap/libpcap-67/libpcap/pcapng.c.auto.html
 *
 *
 * get_opthdr_from_block_data und der get_optvalue
 *
 * rudimentär: https://wiki.wireshark.org/Development/PcapNg?action=AttachFile&do=view&target=ntartest.c
 * reicht für Fortschritts-Test
 *
 * https://pcapng.github.io/pcapng/#rfc.section.4.1
 * http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
 */
