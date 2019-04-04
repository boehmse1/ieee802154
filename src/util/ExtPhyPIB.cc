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
    // assign the message names for lower Layer messages (typically confirms)
    mappedlowerMsgTypes["PLME-SET.confirm"] = SET;
    // assign the message names for Upper Layer messages (typically requests)
    mappedupperMsgTypes["PLME-GET.request"] = GET;
    mappedupperMsgTypes["PLME-SET.request"] = SET;
    mappedupperMsgTypes["PLME-SET-PHY-PIB.request"] = SETREQUPPIB;
    mappedupperMsgTypes["PLME-GET-PHY-PIB.request"] = GETREQUPPIB;


    phyCurrentChannel=par("phyCurrentChannel");
   // phyChannelsSupported[1]=par("phyChannelsSupported");
    phyChannelsSupported={0,1};
    phyTransmitPower=par("phyTransmitPower");
    phyCCAMode=par("phyCCAMode");
    phyCurrentPage=par("phyCurrentPage");
    phyMaxFrameDuration=par("phyMaxFrameDuration");
    phySHRDuration=par("phySHRDuration");
    phySymbolsPerOctet=par("phySymbolsPerOctet");
    phyLQI=par("phyLQI");
    phytxgain=par("phytxgain");
    phyrxgain=par("phyrxgain");
    phybandwidth=par("phybandwidth");
    physampling_rate=par("physampling_rate");

    cModule *nic = getParentModule();

    for (cModule::SubmoduleIterator i(nic); !i.end(); i++) {
          cModule *submodp = i();
          // todo: by name?
          if (std::string(submodp->getFullName()) == "PHY") {
              phyID = submodp->getId();
              std::cout<<"found it"<<std::endl;
          }
      }
    queue = new cQueue();
}

void ExtPhyPIB::handleMessage(cMessage *msg)
{
    switch (mappedupperMsgTypes[msg->getName()]) // --> PHY-Management Service Primitives
            {
                case SETREQUPPIB: {
                    SetPPIBRequest *preq=check_and_cast<SetPPIBRequest*>(msg);
                    if(msg->getSenderModuleId()==phyID){ // --> only extPHY is allowed to set the values
                            setPhyCcaMode(preq->getPIBcca());
                            setPhyCurrentChannel(preq->getPIBcurcha());
                            setPhyCurrentPage(preq->getPIBcurpag());
                            setPhyLqi(preq->getPIBLQI());
                            setPhyMaxFrameDuration(preq->getPIBmaxframs());
                            setPhyShrDuration(preq->getPIBshdr());
                            setPhySymbolsPerOctet(preq->getPIBsymOc());
                            setPhyTransmitPower(preq->getPIBtrPwr());
                            setPhytxgain(preq->getPIBtxgain());
                            setPhyrxgain(preq->getPIBrxgain());
                            setPhybandwidth(preq->getPIBbandwidth());
                            setPhysamplingRate(preq->getPIBsamprate());
                            setPhySignalStrenght(preq->getPIBsignalstrengt());
                            SetPPIBConfirm *pcon=new SetPPIBConfirm("PLME-SET-PHY-PIB.confirm");
                            pcon->setStatus(phy_SUCCESS);
                            sendDirect(pcon,msg->getSenderModule(),"inFromExt");
                            cancelAndDelete(msg);

                    }else{
                        SetPPIBConfirm *pcon=new SetPPIBConfirm();
                        pcon->setStatus(phy_UNSUPPORT_ATTRIBUTE);
                        sendDirect(pcon,msg->getSenderModule(),"inFromExt");
                        cancelAndDelete(msg);
                    }
                    return;
                }
                case GETREQUPPIB:{

                    GetPPIBConfirm* pcon=new GetPPIBConfirm("PLME-GET-PHY-PIB.confirm");
                    pcon->setStatus(phy_SUCCESS);
                    pcon->setPIBcca(getPhyCcaMode());
                    pcon->setPIBcurcha(getPhyCurrentChannel());
                    pcon->setPIBcurpag(getPhyCurrentPage());
                    pcon->setPIBchansup(0);
                    pcon->setPIBLQI(getPhyLqi());
                    pcon->setPIBshdr(getPhyShrDuration());
                    pcon->setPIBsymOc(getPhySymbolsPerOctet());
                    pcon->setPIBtrPwr(getPhyTransmitPower());
                    pcon->setPIBtxgain(getPhytxgain());
                    pcon->setPIBrxgain(getPhyrxgain());
                    pcon->setPIBbandwidth(getPhybandwidth());
                    pcon->setPIBsamprate(getPhysamplingRate());
                    pcon->setPIBsignalstrength(getPhySignalStrenght());

                    sendDirect(pcon,msg->getSenderModule(),"inFromExt");
                    cancelAndDelete(msg);
                    return;
                }
                case GET:{
                    GetRequest *requ=check_and_cast<GetRequest*>(msg);
                    GetConfirm *confmsg=new GetConfirm("PLME-GET.confirm");
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
                        case signalstrength:{
                            confmsg->setValue(getPhySignalStrenght());
                            break;
                        }

                    }
                    sendDirect(confmsg,msg->getSenderModule(),"inFromExt");
                    return;
                }
                case SET:{
                    OpenRequest* opr=new OpenRequest();
                    SetRequest* requ=check_and_cast<SetRequest*>(msg);
                    opr->setModulID(msg->getSenderModule()->getId());
                    opr->setPIBMsgTypes(SET);
                    opr->setPIBattr(requ->getPIBattr());
                    queue->insert(opr);
                    sendDirect(requ,simulation.getModule(phyID),"inFromExt");
                    return;
                }
            }
    switch (mappedlowerMsgTypes[msg->getName()]) // --> PHY-Management Service Primitives
                {
                case SET:{
                     OpenRequest* opr=check_and_cast<OpenRequest*>(queue->pop());
                     SetConfirm* conf=check_and_cast<SetConfirm*>(msg);
                     sendDirect(conf, simulation.getModule(opr->getModulID()), "inFromExt"); // to extPhyPIB
                     break;
                }
                default:{
                    cancelAndDelete(msg);
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

uint8_t ExtPhyPIB::getPhySignalStrenght() const {
    return phySignalStrenght;
}

void ExtPhyPIB::setPhySignalStrenght(uint8_t phySignalStrenght) {
    this->phySignalStrenght = phySignalStrenght;
}
