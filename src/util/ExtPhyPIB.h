//
// Copyright (C) 2013 Matti Schnurbusch (original code)
// Copyright (C) 2014 Michael Kirsche   (clean-up, adaptation for newer 802.15.4 revisions, ported for INET 2.x)
// Copyright (C) 2014 Gino Glodni   (changes for external PIB)
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

// TODO: Check and update for IEEE 802.15.4-2006 revision compliance

#ifndef ExtPhyPIB_H_
#define ExtPhyPIB_H_

#include "math.h"
#include "stdlib.h"
#include "omnetpp.h"
#include "IEEE802154Consts.h"
#include "IEEE802154Enum.h"
#include "PPDU_m.h"

// This Class Represents the PHY - PAN information Base
class ExtPhyPIB : public cSimpleModule
{
    public:
        ExtPhyPIB() {}; // Standard Ctor
        virtual ~ExtPhyPIB() {};   // Standard Dtor

        void handleMessage(cMessage *msg);

        uint32_t getPhybandwidth() const;
        void setPhybandwidth(uint32_t phybandwidth);
        unsigned short getPhyCcaMode() const;
        void setPhyCcaMode(unsigned short phyCcaMode);
        const std::vector<int>& getPhyChannelsSupported() const;
        void setPhyChannelsSupported(const std::vector<int>& phyChannelsSupported);
        unsigned short getPhyCurrentChannel() const;
        void setPhyCurrentChannel(unsigned short phyCurrentChannel);
        unsigned short getPhyCurrentPage() const;
        void setPhyCurrentPage(unsigned short phyCurrentPage);
        uint8_t getPhyLqi() const;
        void setPhyLqi(uint8_t phyLqi);
        unsigned short getPhyMaxFrameDuration() const;
        void setPhyMaxFrameDuration(unsigned short phyMaxFrameDuration);
        uint8_t getPhyrxgain() const;
        void setPhyrxgain(uint8_t phyrxgain);
        uint32_t getPhysamplingRate() const;
        void setPhysamplingRate(uint32_t physamplingRate);
        unsigned short getPhyShrDuration() const;
        void setPhyShrDuration(unsigned short phyShrDuration);
        float getPhySymbolsPerOctet() const;
        void setPhySymbolsPerOctet(float phySymbolsPerOctet);
        unsigned char getPhyTransmitPower() const;
        void setPhyTransmitPower(unsigned char phyTransmitPower);
        uint8_t getPhyTrXstatus() const;
        void setPhyTrXstatus(uint8_t phyTrXstatus);
        uint8_t getPhytxgain() const;
        void setPhytxgain(uint8_t phytxgain);
    uint8_t getPhySignalStrenght() const;
    void setPhySignalStrenght(uint8_t phySignalStrenght);

    protected:
        void initialize ();

        int moduleID;

    private:
        std::map<std::string, PIBMsgTypes> mappedupperMsgTypes;
        std::map<std::string, PIBMsgTypes> mappedlowerMsgTypes;
        unsigned short phyCurrentChannel;
        std::vector<int> phyChannelsSupported;
        unsigned char phyTransmitPower;
        unsigned short phyCCAMode;
        unsigned short phyCurrentPage;
        unsigned short phyMaxFrameDuration;
        unsigned short phySHRDuration;
        double phySymbolsPerOctet;
        uint8_t phyTRXstatus;
        uint8_t phyLQI;
        uint8_t phytxgain;
        uint8_t phyrxgain;
        uint32_t phybandwidth;
        uint32_t physampling_rate;
        uint8_t phySignalStrenght;

        cQueue* queue;

        int phyID=0;


};

#endif /* ExtPhyPIB_H_ */
