#include <netinet/in.h>  //ntohs, ntohl, htons, htonl

inline bpf_u_int32 readByte(unsigned char * buf, int from)
{
    return buf[from];
}

//read in Network Byte Order -> Returns Big Endian Format : 0xa1b2c3d4
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

inline bpf_u_int32 read2Bytes(unsigned char * buf, int from)
{
    bpf_u_int32 value = 0;

    value = buf[from];
    value = (value & 0xFF) << 8;
    value = (value | buf[from + 1]);
    return value;
}

//TODO: read 8 Byte

//read in Layer-2 (Host-Byte-Order) -> Returns Little Endian Format : 0xd4c3b2a1
inline bpf_u_int32 read4BytesNtohl(unsigned char * buf, int from)
{
/*
    #include <stdio.h>
    printf("%02x ",buf[from]);
    printf("%02x ",buf[from + 1]);
    printf("%02x ",buf[from + 2]);
    printf("%02x ",buf[from + 3]);
*/

    bpf_u_int32 value = 0;

    value = buf[from + 3] << 24;
    value = value | (buf[from + 2] << 16);
    value = value | (buf[from + 1] << 8);
    value = value | buf[from + 0];

    //printf("\n%08x ",value);
    //printf("\n%08x ",ntohl(value));

    return value;
}


inline bpf_u_int32 read2BytesNtohs(unsigned char * buf, int from)
{
    bpf_u_int32 value = 0;

    value = buf[from + 1] << 8;
    value = value | (buf[from]);

    return value;
}
