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

#ifndef BUFFER_H_
#define BUFFER_H_

#include "base/INETDefs.h"

/**
 * Buffer for serializer/deserializer
 */
class INET_API Buffer
{
  protected:
    unsigned char *buf = nullptr;
    unsigned int bufsize = 0;
    mutable unsigned int pos = 0;
    mutable bool errorFound = false;

public:
    Buffer(const Buffer& base, unsigned int maxLength);
    Buffer(void *buf, unsigned int bufLen) :
            buf(static_cast<unsigned char *>(buf)), bufsize(bufLen) {
    }

    // position
    void seek(unsigned int newpos) const {
        if (newpos <= bufsize) {
            pos = newpos;
        } else {
            pos = bufsize;
            errorFound = true;
        }
    }
    unsigned int getPos() const {
        return pos;
    }
    unsigned int getRemainingSize() const {
        return bufsize - pos;
    }
    unsigned int getRemainingSize(unsigned int reservedSize) const {
        return bufsize - pos > reservedSize ? (bufsize - pos) - reservedSize : 0;
    }

    bool hasError() const {
        return errorFound;
    }
    void setError() const {
        errorFound = true;
    }

    // read
    unsigned char readByte() const;  // returns 0 when not enough space
    void readNBytes(unsigned int length, void *dest) const; // padding with 0 when not enough space
    uint16_t readUint16NtoH() const; // ntoh, padding with 0 when not enough bytes
    uint16_t readUint16() const;
    uint32_t readUint32NtoH() const; // ntoh, padding with 0 when not enough bytes
    uint32_t readUint32() const;
    uint64_t readUint64NtoH() const; // ntoh, padding with 0 when not enough bytes
    uint64_t readUint64() const;

    // write
    void writeByte(unsigned char data);
    void writeByteTo(unsigned int position, unsigned char data);
    void writeNBytes(unsigned int length, const void *src);
    void writeNBytes(Buffer& inputBuffer, unsigned int length);

    void fillNBytes(unsigned int length, unsigned char data);
    void writeUint16HtoN(uint16_t data);    // hton
    void writeUint16(uint16_t data);
    void writeUint16ToHtoN(unsigned int position, uint16_t data);    // hton
    void writeUint16To(unsigned int position, uint16_t data);
    void writeUint32HtoN(uint32_t data);    // hton
    void writeUint32(uint32_t data);
    void writeUint64HtoN(uint64_t data);    // hton
    void writeUint64(uint64_t data);

    // read/write
    void *accessNBytes(unsigned int length); // returns nullptr when haven't got enough space
    const void *accessNBytes(unsigned int length) const {
        return const_cast<Buffer *>(this)->accessNBytes(length);
    }    // returns nullptr when haven't got enough space

    // print
    char *getByteStream();
    char *getByteStream(unsigned int length);

    // reset
    void reset();

    // reverse
    unsigned short reverse(unsigned short c) const;

    //TODO bit manipulation???

    //DEPRECATED:
    unsigned char *_getBuf() const { return buf; }
    unsigned int _getBufSize() const { return bufsize; }
};

#endif  // BUFFER_H_

