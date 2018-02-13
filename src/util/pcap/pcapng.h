//Copyright (c) 2016, CoRE Research Group, Hamburg University of Applied Sciences
//All rights reserved.
//
//Redistribution and use in source and binary forms, with or without modification,
//are permitted provided that the following conditions are met:
//
//1. Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
//2. Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
//3. Neither the name of the copyright holder nor the names of its contributors
//   may be used to endorse or promote products derived from this software without
//   specific prior written permission.
//
//THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
//ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
//ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/*
 * Before modification sourcecode comes from CoRE Research Group, Hamburg University of Applied Sciences.
 * Modification based on source: libpcap-1.8.1/sf-pcap-ng.c
 * and https://opensource.apple.com/source/libpcap/libpcap-67
 * the apple libpcap sourcefiles, https://opensource.apple.com/source/libpcap/libpcap-67/libpcap/pcapng.c.auto.html
 */

#ifndef PCAPNG_H_
#define PCAPNG_H_

#include <sys/types.h>
#include <stdint.h>
#include <pcap.h>
#include <assert.h>
/*
 * Block types.
 */
#define BT_SHB 0x0A0D0D0A         /* Section Header Block */
#define BT_RES 0x00000000         /* Reserved */
#define BT_IDB 0x00000001         /* Interface Description Block */
#define BT_PB  0x00000002         /* Packet Block */  //obsolet
#define BT_SPB 0x00000003         /* Simple Packet Block */
#define BT_NRB 0x00000004         /* Name Resolution Block */
#define BT_ISB 0x00000005         /* Interface Statistics Block */
#define BT_EPB 0x00000006         /* Enhanced Packet Block */
#define BT_CB  0x00000BAD         /* Custom Block */
#define BT_CB2 0x40000BAD         /* Custom Block */
//Experimental Blocks are not documented yet, see http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html or https://pcapng.github.io/pcapng/


/*
 * Common part at the beginning of all blocks.
 */
typedef struct {
    uint32_t block_type;
    uint32_t total_length;
} block_header;

/*
 * Common trailer at the end of all blocks.
 */
typedef struct {
    uint32_t total_length;
} block_trailer;

/*
 * Common options.
 */
#define OPT_ENDOFOPT    0   /* end of options */
#define OPT_COMMENT 1   /* comment string */

/*
 * Option header.
 */
typedef struct {
    uint16_t     option_code;
    uint16_t     option_length;
} option_header;


/*
 * Structures for the part of each block type following the common
 * part.
 */

/*
 * Section Header Block.
 */
#define BT_SHB          0x0A0D0D0A

typedef struct {
    uint32_t    byte_order_magic;
    uint16_t     major_version;
    uint16_t     minor_version;
    uint64_t   section_length;
    /* followed by options and trailer */
} section_header_block;

/*
 * Options in the SHB.
 */
#define SEC_HARDWARE 2  // 2
#define SEC_OS 3        // 3
#define SEC_USERAPPL 4  // 4

//must be UTF-8 string, see https://pcapng.github.io/pcapng/#section_shb

/*
 * Byte-order magic value.
 */
#define BYTE_ORDER_MAGIC         0x1A2B3C4D                 // Big-endian            //defined in standard
#define BYTE_ORDER_MAGIC_LITTLE  0x4D3C2B1A                 // Little-endian
#define BIG_SWAPPED              0xA1B2C3D4                 // Big-endian swapped
#define LITTLE_SWAPPED           0xD4C3B2A1                 // Little-endian swapped


/*
 * Current version number.  If major_version isn't PCAP_NG_VERSION_MAJOR,
 * that means that this code can't read the file.
 */
#define PCAP_NG_VERSION_MAJOR   1
#define PCAP_NG_VERSION_MINOR   0

/*
 * Interface Description Block.
 */
#define BT_IDB          0x00000001

typedef struct {
    uint16_t     linktype;
    uint16_t     reserved;
    uint32_t    snaplen;
    /* followed by options and trailer */
} interface_description_block;

/*
 * Options in the IDB.
 */
#define IF_NAME     2   /* interface name string */
#define IF_DESCRIPTION  3   /* interface description string */
#define IF_IPV4ADDR 4   /* interface's IPv4 address and netmask */
#define IF_IPV6ADDR 5   /* interface's IPv6 address and prefix length */
#define IF_MACADDR  6   /* interface's MAC address */
#define IF_EUIADDR  7   /* interface's EUI address */
#define IF_SPEED    8   /* interface's speed, in bits/s */
#define IF_TSRESOL  9   /* interface's time stamp resolution */
#define IF_TZONE    10  /* interface's time zone */
#define IF_FILTER   11  /* filter used when capturing on interface */
#define IF_OS       12  /* string OS on which capture on this interface was done */
#define IF_FCSLEN   13  /* FCS length for this interface */
#define IF_TSOFFSET 14  /* time stamp offset for this interface */

/*
 * Linktypes in the IDB.
 */
#define IDB_LINKTYPE_NULL 0
#define IDB_LINKTYPE_ETHERNET   1
#define IDB_LINKTYPE_CAN20B 190
#define IDB_LINKTYPE_FLEXRAY 210
#define IDB_LINKTYPE_SOCKETCAN 227
#define IDB_LINKTYPE_NETANALYZER_TRANSPARENT 241
#define DLT_IEEE802_15_4    195           /* LINKTYPE_IEEE802_15_4, with each packet having FCS at the end of the frame */
#define DLT_IEEE802_15_4_NONASK_PHY 215   /* LINKTYPE_IEEE802_15_4_NONASK_PHY */
#define DLT_IEEE802_15_4_NOFCS 230        /* LINKTYPE_IEEE802_15_4_NOFCS, without the FCS at the end of the frame */

/*
 * Packet Block
 * this BlockType is obsolete and define is only here to mark as obsolete Packet Block, see STd.
 */
#define BT_PB           0x00000002

/*
 * Enhanced Packet Block.
 */
#define BT_EPB          0x00000006

typedef struct {
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t caplen;
    uint32_t len;
    /* followed by packet data, options, and trailer */
} enhanced_packet_block;

#define EP_FLAGS 2         /* 32 bits flags word containing link-layer information */
#define EP_HASH 3          /* Variable length */
#define EP_DROPCOUNT 4


/* Simple Packet Block (SPB) - ID 0x00000003 */
typedef struct {
    u_int32_t   len;  /* length of packet when transmitted (was -orig_len- in classic pcap packet header) */
} simple_packet_block;

/* Name Resolution Block (NRB) - ID 0x00000004 */
typedef struct {
    u_int16_t       record_type;    /* type of record (ipv4 / ipv6) */
    u_int16_t       record_length;  /* length of record value */
} name_resolution_block;

/* Interface Statistics Block - ID 0x00000005 */
typedef struct {
    u_int32_t   interface_id;     /* the interface the stats refer to - identified by interface description block in current section */
    u_int32_t   timestamp_high;   /* high bytes of timestamp */
    u_int32_t   timestamp_low;    /* low bytes of timestamp */
} interface_statistics_block;


//added from libpcap
/*
 * Block cursor - used when processing the contents of a block.
 * Contains a pointer into the data being processed and a count
 * of bytes remaining in the block.
 */
struct block_cursor {
    u_char      *data;
    size_t      data_remaining;
    bpf_u_int32 block_type;
};

typedef enum {
    PASS_THROUGH,
    SCALE_UP_DEC,
    SCALE_DOWN_DEC,
    SCALE_UP_BIN,
    SCALE_DOWN_BIN
} tstamp_scale_type_t;

/*
 * Per-interface information.
 */
struct pcap_ng_if {
    u_int tsresol;          /* time stamp resolution */
    tstamp_scale_type_t scale_type; /* how to scale */
    u_int scale_factor;     /* time stamp scale factor for power-of-10 tsresol */
    u_int64_t tsoffset;     /* time stamp offset */
};

struct pcap_ng_sf {
    u_int user_tsresol;     /* time stamp resolution requested by the user */
    bpf_u_int32 ifcount;        /* number of interfaces seen in this capture */
    bpf_u_int32 ifaces_size;    /* size of array below */
    struct pcap_ng_if *ifaces;  /* array of interface information */
};

#endif /* PCAPNG_H_ */
