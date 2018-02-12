//
// Copyright (C) 2016 Sebastian Boehm (BTU-CS) (Adaption for IEEE802154Serializer)
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

#include "Buffer.h"

Buffer::Buffer(const Buffer& base, unsigned int maxLength)
{
    buf = base.buf + base.pos;
    bufsize = std::min(base.bufsize - base.pos, maxLength);
}

unsigned char Buffer::readByte() const
{
    if (pos >= bufsize) {
        errorFound = true;
        return 0;
    }
    return buf[pos++];
}

void Buffer::readNBytes(unsigned int length, void *_dest) const
{
    unsigned char *dest = static_cast<unsigned char *>(_dest);
    while (length--) {
        if (pos >= bufsize) {
            errorFound = true;
            *dest++ = 0;
        } else
            *dest++ = buf[pos++];
    }
}

uint16_t Buffer::readUint16NtoH() const
{
    uint16_t ret = 0;
    if (pos < bufsize) ret += ((uint16_t)(buf[pos++]) << 8);
    if (pos < bufsize) ret += ((uint16_t)(buf[pos++]));
    else errorFound = true;
    return ret;
}

uint16_t Buffer::readUint16() const
{
    uint16_t ret = 0;
    if (pos < bufsize) ret += ((uint16_t)(buf[pos++]));
    if (pos < bufsize) ret += ((uint16_t)(buf[pos++]) << 8);
    else errorFound = true;
    return ret;
}

uint32_t Buffer::readUint32NtoH() const
{
    uint32_t ret = 0;
    if (pos < bufsize) ret += ((uint32_t)(buf[pos++]) << 24);
    if (pos < bufsize) ret += ((uint32_t)(buf[pos++]) << 16);
    if (pos < bufsize) ret += ((uint32_t)(buf[pos++]) <<  8);
    if (pos < bufsize) ret += ((uint32_t)(buf[pos++]));
    else errorFound = true;
    return ret;
}

uint32_t Buffer::readUint32() const
{
    uint32_t ret = 0;
    if (pos < bufsize) ret += ((uint32_t)(buf[pos++]));
    if (pos < bufsize) ret += ((uint32_t)(buf[pos++]) << 8);
    if (pos < bufsize) ret += ((uint32_t)(buf[pos++]) << 16);
    if (pos < bufsize) ret += ((uint32_t)(buf[pos++]) << 24);
    else errorFound = true;
    return ret;
}

uint64_t Buffer::readUint64NtoH() const
{
    uint64_t ret = 0;
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]) << 56);
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]) << 48);
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]) << 40);
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]) << 32);
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]) << 24);
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]) << 16);
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]) <<  8);
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]));
    else errorFound = true;
    return ret;
}

uint64_t Buffer::readUint64() const
{
    uint64_t ret = 0;
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]));
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]) << 8);
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]) << 16);
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]) << 24);
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]) << 32);
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]) << 40);
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]) << 48);
    if (pos < bufsize) ret += ((uint64_t)(buf[pos++]) << 56);
    else errorFound = true;
    return ret;
}

void Buffer::writeByte(unsigned char data)
{
    if (pos >= bufsize) {
        errorFound = true;
        return;
    }
    buf[pos++] = data;
}

void Buffer::writeByteTo(unsigned int position, unsigned char data)
{
    if (position >= bufsize) {
        errorFound = true;
        return;
    }
    buf[position] = data;
}

void Buffer::writeNBytes(unsigned int length, const void *_src)
{
    const unsigned char *src = static_cast<const unsigned char *>(_src);
    while (pos < bufsize && length > 0) {
        buf[pos++] = *src++;
        length--;
    }
    if (length)
        errorFound = true;
}

void Buffer::writeNBytes(Buffer& inputBuffer, unsigned int length)
{
    while (pos < bufsize && length > 0) {
        buf[pos++] = inputBuffer.readByte();
        length--;
    }
    if (length)
        errorFound = true;
}

void Buffer::fillNBytes(unsigned int length, unsigned char data)
{
    while (pos < bufsize && length > 0) {
        buf[pos++] = data;
        length--;
    }
    if (length)
        errorFound = true;
}

void Buffer::writeUint16HtoN(uint16_t data)    // hton
{
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 8);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)data;
    else
        errorFound = true;
}

void Buffer::writeUint16(uint16_t data)
{
    if (pos < bufsize)
        buf[pos++] = (uint8_t)data;
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 8);
    else
        errorFound = true;
}

void Buffer::writeUint16ToHtoN(unsigned int position, uint16_t data)    // hton
{
    if (position < bufsize)
        buf[position++] = (uint8_t)(data >> 8);
    if (position < bufsize)
        buf[position++] = (uint8_t)data;
    else
        errorFound = true;
}

void Buffer::writeUint16To(unsigned int position, uint16_t data)
{
    if (position < bufsize)
        buf[position++] = (uint8_t)data;
    if (position < bufsize)
        buf[position++] = (uint8_t)(data >> 8);
    else
        errorFound = true;
}

void Buffer::writeUint32HtoN(uint32_t data)    // hton
{
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 24);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 16);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 8);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)data;
    else
        errorFound = true;
}

void Buffer::writeUint32(uint32_t data)
{
    if (pos < bufsize)
        buf[pos++] = (uint8_t)data;
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 8);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 16);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 24);
    else
        errorFound = true;
}

void Buffer::writeUint64HtoN(uint64_t data)    // hton
{
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 56);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 48);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 40);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 32);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 24);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 16);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 8);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)data;
    else
        errorFound = true;
}

void Buffer::writeUint64(uint64_t data)
{
    if (pos < bufsize)
        buf[pos++] = (uint8_t)data;
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 8);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 16);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 24);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 32);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 40);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 48);
    if (pos < bufsize)
        buf[pos++] = (uint8_t)(data >> 56);
    else
        errorFound = true;
}

void *Buffer::accessNBytes(unsigned int length)
{
    if (pos + length <= bufsize) {
        void *ret = buf + pos;
        pos += length;
        return ret;
    }
    pos = bufsize;
    errorFound = true;
    return nullptr;
}

char *Buffer::getByteStream()
{
    char* bufstream = new char[bufsize];
    char temp[32] = "";
    sprintf(temp, "Buffer[%u]: ", bufsize);
    strcpy(bufstream, temp);
    for (unsigned int i=0; i<bufsize; i++) {
        memset(temp, 0, sizeof(*temp));
        sprintf(temp, "0x%x,", buf[i]);
        strcat(bufstream, temp);
    }
    return bufstream;
}

char *Buffer::getByteStream(unsigned int length)
{
    char* bufstream = new char[length];
    char temp[32] = "";
    sprintf(temp, "Buffer[%u]: ", length);
    strcpy(bufstream, temp);
    for (unsigned int i=0; i<length; i++) {
        memset(temp, 0, sizeof(*temp));
        sprintf(temp, "0x%x,", buf[i]);
        strcat(bufstream, temp);
    }
    return bufstream;
}

void Buffer::reset()
{
    buf = nullptr;
    bufsize = 0;
    pos = 0;
    errorFound = false;
}

unsigned short Buffer::reverse(unsigned short c) const
{
   int shift;
   unsigned short result = 0;
   for (shift = 0; shift < 16; shift++) {
      if (c & (0x01 << shift))
         result |= (0x8000 >> shift);
   }
   return result;
}
