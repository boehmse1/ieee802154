//
// Copyright (C) 2018 Sebastian Boehm (BTU-CS)
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
#pragma once
#ifndef IEEE802154SERIALIZER_H_
#define IEEE802154SERIALIZER_H_

#include <omnetpp.h>

#include "IEEE802154Enum.h"
#include "Buffer.h"
#include "MPDU_m.h"
#include "RawPacket.h"

#define sEV (ev.isDisabled()||!sDebug) ? std::cout : std::cout << "[802154_Serializer]: "    // switchable debug output

/** ------- PHY Data Service Primitive Header Lengths --------- */

/** @brief Maximum PHY message header size */
#define maxPHYMessageHeaderSize 4;

/** @brief Size in bytes of PD_DATA_REQUEST message header */
#define SIZEOF_PD_DATA_REQUEST                  3

/** @brief Size in bytes of PD_DATA_CONFIRM message header */
#define SIZEOF_PD_DATA_CONFIRM                  3

/** @brief Size in bytes of PD_DATA_INDICATION message header */
#define SIZEOF_PD_DATA_INDICATION               4

/** @brief Size in bytes of PLME_CCA_REQUEST message header */
#define SIZEOF_PLME_CCA_REQUEST                 2

/** @brief Size in bytes of PLME_CCA_CONFIRM message header */
#define SIZEOF_PLME_CCA_CONFIRM                 3

/** @brief Size in bytes of PLME_ED_REQUEST message header */
#define SIZEOF_PLME_ED_REQUEST                  2

/** @brief Size in bytes of PLME_ED_CONFIRM message header */
#define SIZEOF_PLME_ED_CONFIRM                  4

/** @brief Size in bytes of PLME_GET_REQEST message header */
#define SIZEOF_PLME_GET_REQUEST                  3

/** @brief Size in bytes of PLME_GET_CONFIRM message header */
#define SIZEOF_PLME_GET_CONFIRM                 4

/** @brief Size in bytes of PLME_SET_TRX_STATE_REQUEST message header */
#define SIZEOF_PLME_SET_TRX_STATE_REQUEST       3

/** @brief Size in bytes of PLME_SET_TRX_STATE_CONFIRM message header */
#define SIZEOF_PLME_SET_TRX_STATE_CONFIRM       3

/** @brief Size in bytes of PLME_SET_REQUEST message header */
#define SIZEOF_PLME_SET_REQUEST                 3

/** @brief Size in bytes of PLME_SET_CONFIRM message header */
#define SIZEOF_PLME_SET_CONFIRM                 4

/** @brief Size in bytes of PLME_SET_CONFIRM message header */
#define SIZEOF_RF_INDICATION                    3

/**
 * Converts between IEEE 802.15.4 frame and network byte order
 */
class IEEE802154Serializer
{
    public:
        IEEE802154Serializer() {}
        virtual ~IEEE802154Serializer() {}
        virtual void serialize(const cPacket *pkt, Buffer &b);
        virtual cPacket* deserialize(const Buffer &b);
        virtual void serializeSDU(cMessage *msg, Buffer &b);
        virtual cMessage* deserializeSDU(const Buffer &b);

    protected:
        /** @brief Debug output switch for the IEEE 802.15.4 Serializer module */
        bool sDebug = true;

        std::map<std::string, PIBMsgTypes> msgTypes; // messages from upper layer are typically requests
};

#endif /* IEEE802154SERIALIZER_H_ */
