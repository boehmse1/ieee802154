//
// Copyright (C) 2018 Sebastian Boehm
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

message PCAPNG
{
    uint32 blockType;   // refer to pcapng.h
    uint32 blockLength; // total block length
}

message SHB extends PCAPNG
{
    uint32 magic;
    uint16 ver_major;
    uint16 ver_minor;
    uint64 sectionLength;
}

message IDB extends PCAPNG
{
    uint16 linktype;
    uint16 reserved;
    uint32 snaplen;
}

message EPB extends PCAPNG
{
    uint32 interface;
    uint32 time_high;
    uint32 time_low;
    uint32 cap_len;
    uint32 orig_len;
    uint8 data[127];
}


