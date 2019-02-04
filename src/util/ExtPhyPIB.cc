//
// Copyright (C) 2013 Matti Schnurbusch (original code)
// Copyright (C) 2014 Michael Kirsche   (clean-up, adaptation for newer 802.15.4 revisions, ported for INET 2.x)
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

#include "ExtPhyPIB.h"
#include "omnetpp.h"

Define_Module(ExtPhyPIB);

void ExtPhyPIB::initialize()
{
    // assign the message names for Upper Layer messages (typically requests)
    mappedMsgTypes["PLME-GET.request"] = GET;
    mappedMsgTypes["PLME-PHY-PIB-UPDATE.confirm"] = CONFPPIB;

    cModule *host = getParentModule();
    this->getId();

    std::cout<<"PIBmoduleID "<<this->getId()<<std::endl;

    phyCurrentChannel=par("phyCurrentChannel");
   // phyChannelsSupported[1]=par("phyChannelsSupported");
    phyTransmitPower=par("phyTransmitPower");
    phyCCAMode=par("phyCCAMode");
    phyCurrentPage=par("phyCurrentPage");
    phyMaxFrameDuration=par("phyMaxFrameDuration");
    phySHRDuration=par("phySHRDuration");
    phySymbolsPerOctet=par("phySymbolsPerOctet");
    phyTRXstatus=par("phyTRXstatus");
    phyLQI=par("phyLQI");
    phytxgain=par("phytxgain");
    phyrxgain=par("phyrxgain");
    phybandwidth=par("phybandwidth");
    physampling_rate=par("physampling_rate");
}

void ExtPhyPIB::handleMessage(cMessage *msg)
{
    switch (mappedMsgTypes[msg->getName()]) // --> PHY-Management Confirm Service Primitives
            {
                case CONFPPIB: {
                    PPIBConfirm *pcon=check_and_cast<PPIBConfirm*>(msg);
                    setPhyCcaMode(pcon->getPIBcca());
                    setPhyCurrentChannel(pcon->getPIBcurcha());
                    setPhyCurrentPage(pcon->getPIBcurpag());
    //                setPhyChannelsSupported(pcon->getPIBchansup());
                    setPhyLqi(pcon->getPIBLQI());
                    setPhyMaxFrameDuration(pcon->getPIBmaxframs());
                    setPhyShrDuration(pcon->getPIBshdr());
                    setPhySymbolsPerOctet(pcon->getPIBsymOc());
                    setPhyTransmitPower(pcon->getPIBtrPwr());
                    setPhyTrXstatus(pcon->getPIBtrxSt());
                    setPhytxgain(pcon->getPIBtxgain());
                    setPhyrxgain(pcon->getPIBrxgain());
                    setPhybandwidth(pcon->getPIBbandwidth());
                    setPhysamplingRate(pcon->getPIBsamprate());
                    cancelAndDelete(msg);
                    break;
                }
                case GET:{

                    GetRequest *requ=check_and_cast<GetRequest*>(msg);
                    GetConfirm *confmsg=new GetConfirm();
                    confmsg->setPIBind(requ->getPIBind());
                    confmsg->setPIBattr(requ->getPIBattr());
                    confmsg->setStatus(phy_SUCCESS);
                    switch (requ->getPIBattr()){
                        case currentChannel:{
                            confmsg->setValue(getPhyCurrentChannel());
                            break;
                        }
                        case channelSupported:{
    //                        confmsg.setValue(getPhyChannelsSupported());
                            break;
                        }
                        case transmitPower:{
                            confmsg->setValue(getPhyTransmitPower());
                            break;
                        }
                        case CCA_Mode:{
                            confmsg->setValue(getPhyCcaMode());
                            break;
                        }
                        case currentPage:{
                            confmsg->setValue(getPhyCurrentPage());
                            break;
                        }
                        case maxFrameDuration:{
                            confmsg->setValue(getPhyMaxFrameDuration());
                            break;
                        }
                        case SHRDuration:{
                            confmsg->setValue(getPhyShrDuration());
                            break;
                        }
                        case symbolsPerSecond:{
                            confmsg->setValue(getPhySymbolsPerOctet());
                            break;
                        }
                        case LQI:{
                            confmsg->setValue(getPhyLqi());
                            break;
                        }
                        case rxgain:{
                            confmsg->setValue(getPhyrxgain());
                            break;
                        }
                        case txgain:{
                            confmsg->setValue(getPhytxgain());
                            break;
                        }
                        case bandwidth:{
                            confmsg->setValue(getPhybandwidth());
                            break;
                        }
                        case sampling_rate:{
                            confmsg->setValue(getPhysamplingRate());
                            break;
                        }

                    }
                    sendDirect(confmsg,simulation.getModule(msg->getSenderModule()->getId()),"inFromExt");
                    break;
                }
            }
}

uint32_t ExtPhyPIB::getPhybandwidth() const {
    return phybandwidth;
}

void ExtPhyPIB::setPhybandwidth(uint32_t phybandwidth) {
    this->phybandwidth = phybandwidth;
}

unsigned short ExtPhyPIB::getPhyCcaMode() const {
    return phyCCAMode;
}

void ExtPhyPIB::setPhyCcaMode(unsigned short phyCcaMode) {
    phyCCAMode = phyCcaMode;
}

const std::vector<int>& ExtPhyPIB::getPhyChannelsSupported() const {
    return phyChannelsSupported;
}

void ExtPhyPIB::setPhyChannelsSupported(
        const std::vector<int>& phyChannelsSupported) {
    this->phyChannelsSupported = phyChannelsSupported;
}

unsigned short ExtPhyPIB::getPhyCurrentChannel() const {
    return phyCurrentChannel;
}

void ExtPhyPIB::setPhyCurrentChannel(unsigned short phyCurrentChannel) {
    this->phyCurrentChannel = phyCurrentChannel;
}

unsigned short ExtPhyPIB::getPhyCurrentPage() const {
    return phyCurrentPage;
}

void ExtPhyPIB::setPhyCurrentPage(unsigned short phyCurrentPage) {
    this->phyCurrentPage = phyCurrentPage;
}

uint8_t ExtPhyPIB::getPhyLqi() const {
    return phyLQI;
}

void ExtPhyPIB::setPhyLqi(uint8_t phyLqi) {
    phyLQI = phyLqi;
}

unsigned short ExtPhyPIB::getPhyMaxFrameDuration() const {
    return phyMaxFrameDuration;
}

void ExtPhyPIB::setPhyMaxFrameDuration(unsigned short phyMaxFrameDuration) {
    this->phyMaxFrameDuration = phyMaxFrameDuration;
}

uint8_t ExtPhyPIB::getPhyrxgain() const {
    return phyrxgain;
}

void ExtPhyPIB::setPhyrxgain(uint8_t phyrxgain) {
    this->phyrxgain = phyrxgain;
}

uint32_t ExtPhyPIB::getPhysamplingRate() const {
    return physampling_rate;
}

void ExtPhyPIB::setPhysamplingRate(uint32_t physamplingRate) {
    physampling_rate = physamplingRate;
}

unsigned short ExtPhyPIB::getPhyShrDuration() const {
    return phySHRDuration;
}

void ExtPhyPIB::setPhyShrDuration(unsigned short phyShrDuration) {
    phySHRDuration = phyShrDuration;
}

float ExtPhyPIB::getPhySymbolsPerOctet() const {
    return phySymbolsPerOctet;
}

void ExtPhyPIB::setPhySymbolsPerOctet(float phySymbolsPerOctet) {
    this->phySymbolsPerOctet = phySymbolsPerOctet;
}

unsigned char ExtPhyPIB::getPhyTransmitPower() const {
    return phyTransmitPower;
}

void ExtPhyPIB::setPhyTransmitPower(unsigned char phyTransmitPower) {
    this->phyTransmitPower = phyTransmitPower;
}

uint8_t ExtPhyPIB::getPhyTrXstatus() const {
    return phyTRXstatus;
}

void ExtPhyPIB::setPhyTrXstatus(uint8_t phyTrXstatus) {
    phyTRXstatus = phyTrXstatus;
}

uint8_t ExtPhyPIB::getPhytxgain() const {
    return phytxgain;
}

void ExtPhyPIB::setPhytxgain(uint8_t phytxgain) {
    this->phytxgain = phytxgain;
}
