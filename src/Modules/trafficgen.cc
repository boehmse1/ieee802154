//
// Copyright (C) 2000 Institut fuer Telematik, Universitaet Karlsruhe
// Copyright (C) 2004-2005 Andras Varga
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


#include "trafficgen.h"

#include "ModuleAccess.h"
#include "NodeOperations.h"
#include "IPvXAddressResolver.h"
#include "IPSocket.h"
#include "IPv4ControlInfo.h"
#include "IPv6ControlInfo.h"


Define_Module(trafficgen);

simsignal_t trafficgen::rcvdPkSignal = registerSignal("rcvdPk");
simsignal_t trafficgen::sentPkSignal = registerSignal("sentPk");

trafficgen::trafficgen()
{
    timer = NULL;
    nodeStatus = NULL;
    packetLengthPar = NULL;
    sendIntervalPar = NULL;
}

trafficgen::~trafficgen()
{
    cancelAndDelete(timer);
}

void trafficgen::initialize(int stage)
{
    cSimpleModule::initialize(stage);

    // because of IPvXAddressResolver, we need to wait until interfaces are registered,
    // address auto-assignment takes place etc.
    if (stage == 0)
    {
        mappedMsgTypes["PLME-GET.confirm"] = GET;
        mappedMsgTypes["PLME-SET.confirm"] = SET;
        mappedMsgTypes["PLME-GET-PHY-PIB.confirm"] = GETCONFPPIB;
        mappedMlmeMsgTypes["MLME-SCAN.confirm"] = MLMESCAN;
        protocol = par("protocol");
        numPackets = par("numPackets");
        startTime = par("startTime");
        stopTime = par("stopTime");
        if (stopTime >= SIMTIME_ZERO && stopTime < startTime)
            error("Invalid startTime/stopTime parameters");

        packetLengthPar = &par("packetLength");
        sendIntervalPar = &par("sendInterval");

        numSent = 0;
        numReceived = 0;
        lqi=0;
        rxGain=0;
        ED=0;
        WATCH(lqi);
        WATCH(rxGain);
        WATCH(ED);
        WATCH(numSent);
        WATCH(numReceived);
        lqihist.setName("LQIstats");
        lqihist.setRangeAutoUpper(0,255,10);
        lqivec.setName("lqivec");
        EDhist.setName("EDstats");
        EDhist.setRangeAutoUpper(0,255,10);
        EDvec.setName("EDvec");
        rxgainhist.setName("rxgainstats");
        rxgainhist.setRangeAutoUpper(0,255,10);
        rxgainvec.setName("rxgainvec");



        //  search for modules
        cModule *host = getParentModule();
        cModule *nic;

        for (cModule::SubmoduleIterator i(host); !i.end(); i++) {
             cModule *submodp = i();
             // todo: by name?
             if (std::string(submodp->getFullName()) == "NIC") {
                 nicID = submodp->getId();
                 nic=submodp;
             }
       }

                for (cModule::SubmoduleIterator i(nic); !i.end(); i++) {
                    cModule *submodp = i();
                    // todo: by name?
                    if (std::string(submodp->getFullName()) == "ExtPhyPIB") {
                        ppibID = submodp->getId();
                    }
                }

    }
    else if (stage == 3)
    {
        IPSocket ipSocket(gate("ipOut"));
        ipSocket.registerProtocol(protocol);
        ipSocket.setOutputGate(gate("ipv6Out"));
        ipSocket.registerProtocol(protocol);
    }
}

void trafficgen::startApp()
{
    if (isEnabled())
        scheduleNextPacket(-1);
}

void trafficgen::finish(){

    EV << "Recieved: "<< numReceived<< endl;
    lqihist.recordAs("LQI");
    EDhist.recordAs("ED");
    rxgainhist.recordAs("rxGain");
    std::cout<<"called finish"<<std::endl;
}

void trafficgen::handleMessage(cMessage *msg)
{
    numReceived++;
    bool returnvar=false;
    std::cout<<"in handle message"<<std::endl;
    if (!isNodeUp()){
        throw cRuntimeError("Application is not running");
    }
    if (mappedMsgTypes[msg->getName()]==GETCONFPPIB){

        GetPPIBConfirm *conf=check_and_cast<GetPPIBConfirm*>(msg);
        lqi=conf->getPIBLQI();
        rxGain=conf->getPIBrxgain();
        ED=conf->getPIBsignalstrength();

        lqihist.collect(lqi);
        lqivec.record(lqi);
        EDhist.collect(ED);
        EDvec.record(ED);
        rxgainhist.collect(rxGain);
        rxgainvec.record(rxGain);

        if(conf->getPIBLQI()==255){
            std::cout<<"RX gain = "<< rxGain<<std::endl;
            SetRequest* PhyPIBSet=new SetRequest("PLME-SET.request");
            PhyPIBSet->setPIBattr(rxgain);
            if(rxGain<=51){
                PhyPIBSet->setValue(rxGain-1);
            }else if(rxGain<=65){
                PhyPIBSet->setValue(rxGain-2);
            }else if(rxGain<=115){
                PhyPIBSet->setValue(rxGain-5);
            }
            sendDirect(PhyPIBSet,simulation.getModule(ppibID), "inDirect");

        }
        if(lqi<255){
            SetRequest* PhyPIBSet=new SetRequest("PLME-SET.request");
            PhyPIBSet->setPIBattr(rxgain);
            if(ED<252){
                if(rxGain<=51){
                    PhyPIBSet->setValue(rxGain+1);
                }else if(rxGain<=65){
                    PhyPIBSet->setValue(rxGain+2);
                }else if(rxGain<=115){
                    PhyPIBSet->setValue(rxGain+5);
                }
            }else{
                if(rxGain<=51){
                    PhyPIBSet->setValue(rxGain-1);
                }else if(rxGain<=65){
                    PhyPIBSet->setValue(rxGain-2);
                }else if(rxGain<=115){
                    PhyPIBSet->setValue(rxGain-5);
                }
            }
            sendDirect(PhyPIBSet,simulation.getModule(ppibID), "inDirect");
        }

        returnvar=true;
    }
    if (mappedMsgTypes[msg->getName()]==SET){
        cancelAndDelete(msg);
        returnvar=true;
    }

    if(!returnvar){
        GetPPIBRequest* PhyPIBGet=new GetPPIBRequest("PLME-GET-PHY-PIB.request");
        sendDirect(PhyPIBGet,simulation.getModule(ppibID), "inDirect");
        processPacket(PK(msg));
    }


    if (ev.isGUI())
    {
        char buf[40];
        sprintf(buf, "rcvd: %d pks\nsent: %d pks", numReceived, numSent);
        getDisplayString().setTagArg("t", 0, buf);
    }
}

bool trafficgen::handleOperationStage(LifecycleOperation *operation, int stage, IDoneCallback *doneCallback)
{
    Enter_Method_Silent();
    if (dynamic_cast<NodeStartOperation *>(operation)) {
        if (stage == NodeStartOperation::STAGE_APPLICATION_LAYER)
            startApp();
    }
    else if (dynamic_cast<NodeShutdownOperation *>(operation)) {
        if (stage == NodeShutdownOperation::STAGE_APPLICATION_LAYER)
            cancelNextPacket();
    }
    else if (dynamic_cast<NodeCrashOperation *>(operation)) {
        if (stage == NodeCrashOperation::STAGE_CRASH)
            cancelNextPacket();
    }
    else throw cRuntimeError("Unsupported lifecycle operation '%s'", operation->getClassName());
    return true;
}

void trafficgen::scheduleNextPacket(simtime_t previous)
{
    simtime_t next;
    if (previous == -1)
    {
        next = simTime() <= startTime ? startTime : simTime();
        timer->setKind(START);
    }
    else
    {
        next = previous + sendIntervalPar->doubleValue();
        timer->setKind(NEXT);
    }
    if (stopTime < SIMTIME_ZERO || next < stopTime)
        scheduleAt(next, timer);
}

void trafficgen::cancelNextPacket()
{
    cancelEvent(timer);
}

bool trafficgen::isNodeUp()
{
    return !nodeStatus || nodeStatus->getState() == NodeStatus::UP;
}

bool trafficgen::isEnabled()
{
    return (numPackets == -1 || numSent < numPackets);
}

IPvXAddress trafficgen::chooseDestAddr()
{
    int k = intrand(destAddresses.size());
    return destAddresses[k];
}

void trafficgen::sendPacket()
{
    std::cout<<"in send Packet"<<std::endl;
    char msgName[32];
    sprintf(msgName, "appData-%d", numSent);

    cPacket *payload = new cPacket(msgName);
    payload->setByteLength(packetLengthPar->longValue());

    IPvXAddress destAddr = chooseDestAddr();
    const char *gate;

    if (!destAddr.isIPv6())
    {
        // send to IPv4
        IPv4ControlInfo *controlInfo = new IPv4ControlInfo();
        controlInfo->setDestAddr(destAddr.get4());
        controlInfo->setProtocol(protocol);
        payload->setControlInfo(controlInfo);
        gate = "ipOut";
    }
    else
    {
        // send to IPv6
        IPv6ControlInfo *controlInfo = new IPv6ControlInfo();
        controlInfo->setDestAddr(destAddr.get6());
        controlInfo->setProtocol(protocol);
        payload->setControlInfo(controlInfo);
        gate = "ipv6Out";
    }
    EV << "Sending packet: ";
    printPacket(payload);
    emit(sentPkSignal, payload);
    send(payload, gate);
    numSent++;
}

void trafficgen::printPacket(cPacket *msg)
{
    IPvXAddress src, dest;
    int protocol = -1;

    if (dynamic_cast<IPv4ControlInfo *>(msg->getControlInfo()) != NULL)
    {
        IPv4ControlInfo *ctrl = (IPv4ControlInfo *)msg->getControlInfo();
        src = ctrl->getSrcAddr();
        dest = ctrl->getDestAddr();
        protocol = ctrl->getProtocol();
    }
    else if (dynamic_cast<IPv6ControlInfo *>(msg->getControlInfo()) != NULL)
    {
        IPv6ControlInfo *ctrl = (IPv6ControlInfo *)msg->getControlInfo();
        src = ctrl->getSrcAddr();
        dest = ctrl->getDestAddr();
        protocol = ctrl->getProtocol();
    }

    EV << msg << endl;
    EV << "Payload length: " << msg->getByteLength() << " bytes" << endl;

    if (protocol != -1)
        EV << "src: " << src << "  dest: " << dest << "  protocol=" << protocol << "\n";
}

void trafficgen::processPacket(cPacket *msg)
{
    emit(rcvdPkSignal, msg);
    EV << "Received packet: ";
    printPacket(msg);
    delete msg;
    numReceived++;
}

