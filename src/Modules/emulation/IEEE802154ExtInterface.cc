#include <IEEE802154ExtInterface.h>

Define_Module(IEEE802154ExtInterface);

IEEE802154ExtInterface::IEEE802154ExtInterface()
{
    rtEvent = nullptr;
}

IEEE802154ExtInterface::~IEEE802154ExtInterface()
{
    cancelAndDelete(rtEvent);
    cancelAndDelete(initEvent);
    delete(serializer);
}

void IEEE802154ExtInterface::initialize(int stage)
{
    cSimpleModule::initialize(stage);

    if (stage == 0) {
        rtEvent = new cMessage("rtEvent");
        initEvent = new cMessage("SHB_Event");
        rtScheduler = check_and_cast<PCAPRTScheduler *>(simulation.getScheduler());
        rtScheduler->setInterfaceModule(this, rtEvent, initEvent, recvBuffer, 65536, &numRecvBytes);

        serializer = new IEEE802154Serializer();

        numSent = numRcvd = 0;

        WATCH(numSent);
        WATCH(numRecvBytes);
        WATCH(interfaceTable[0]);
        WATCH(interfaceTable[1]);
        WATCH(interfaceTable[2]);

        cModule *network = getParentModule();

        for (cModule::SubmoduleIterator i(network); !i.end(); i++) {
            cModule *submodp = i();
            if (std::string(submodp->getFullName()) == "IEEE802154Nodes[0]") {
                interfaceTable[0] = submodp->getId();
            }
            if (std::string(submodp->getFullName()) == "IEEE802154Nodes[1]") {
                interfaceTable[1] = submodp->getId();
            }
            if (std::string(submodp->getFullName()) == "IEEE802154Nodes[2]") {
                interfaceTable[2] = submodp->getId();
            }
        }
        extEV << "map: Interface_ID=0:ModuleID= " << interfaceTable[0]
                  << " Interface_ID=1:ModuleID= " << interfaceTable[1]
                  << " Interface_ID=2:ModuleID= " << interfaceTable[2] << endl;
    }

}

void IEEE802154ExtInterface::finish()
{
    extEV << getFullPath() << ": " << numSent << " packets sent, " << numRcvd << " packets received" << endl;
}

void IEEE802154ExtInterface::handleMessage(cMessage *msg)
{
    extEV << "Got Message " << msg->getName() << endl;

    // start of a pcapng stream
    if (dynamic_cast<SHB *>(msg)){
        cancelAndDelete(msg);
    }
    // todo: add interface!
    else if (dynamic_cast<IDB *>(msg)){
        cancelAndDelete(msg);
    }
    // epb packet with encapsulated sdu from extern node
    else if (dynamic_cast<EPB *>(msg)){
        handleEPB(msg);
    }
    // message from intern simulation host
    else if (msg->arrivedOn("inDirect")){
        handleMsgSim(msg);
    }
}

void IEEE802154ExtInterface::handleEPB(cMessage *msg)
{
    extEV << "Handle EPB" << endl;

    unsigned char rtBuffer[1<<16];

    EPB *epb = check_and_cast<EPB *>(msg);
    for (uint8_t i=0; i<epb->getDataArraySize(); i++) {
        rtBuffer[i] = epb->getData(i);
    }

    Buffer b(rtBuffer, epb->getDataArraySize());

    // Message from external interface
    cMessage *sdu;
    sdu = serializer->deserializeSDU(b);

    // corresponding module
    cModule *mod = simulation.getModule(interfaceTable[epb->getInterface()]);
    cModule *phy = mod->getSubmodule("NIC")->getSubmodule("PHY");

    this->sendDirect(sdu, phy, "inFromExt");

    extEV << "send message from extern to simulated Node: " << std::string(mod->getName()) << endl;

    this->numRcvd++;

    cancelAndDelete(msg);
}

void IEEE802154ExtInterface::handleMsgSim(cMessage *msg)
{
    extEV << "Send msg " << msg->getClassName() << " from intern simulation to external devices" << endl;
    unsigned char mybuf[128+32+3];

    int module_id = msg->getSenderModule()->getParentModule()->getParentModule()->getId();
    int interface_id = -1;

    for (unsigned int i=0; i < interfaceTable.size(); i++){
        //extEV << "interfaceTable["<<i<<"]="<<interfaceTable.at(i) << endl;
        if (interfaceTable.at(i) == module_id){
            interface_id = i;
        }
    }

    if (interface_id == -1){
        EV_ERROR << "from Module " << msg->getSenderModule()->getParentModule()->getParentModule()->getName() << " Module_id is not in interfaceTable matching Interface_ID.\n Maybe are in wrong getParentModule()? should be Host" << endl;
    }

    extEV << "interface_id: " << interface_id << " from Module: " << msg->getSenderModule()->getParentModule()->getParentModule()->getName() << "["<<interface_id<<"] = " << module_id << endl;

    Buffer buf(mybuf, 128+32+3);
    //serializer->serialize(mpdu_pkt, buf);
    serializer->serializeSDU(msg, buf);

    rtScheduler->sendEPB(interface_id, msg->getArrivalTime(), buf);
    this->numSent++;

    cancelAndDelete(msg);
}
