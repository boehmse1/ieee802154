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
        initEvent = new cMessage("SHB Event");
        rtScheduler = check_and_cast<PCAPRTScheduler *>(simulation.getScheduler());
        rtScheduler->setInterfaceModule(this, rtEvent, initEvent, recvBuffer, 65536, &numRecvBytes);

        serializer = new IEEE802154Serializer();

        numSent = numRcvd = 0;

        interfaces = 0;

        WATCH(numSent);
        WATCH(numRecvBytes);

        cModule *network = getParentModule();

        // fixme: temp!
        int node = 0;
        for (cModule::SubmoduleIterator i(network); !i.end(); i++) {
            cModule *submodp = i();
            if (std::regex_match(std::string(submodp->getFullName()), std::regex("(IEEE802154Nodes)(.*)"))) {
                interfaceTable[node] = submodp->getId();
                extEV << "Added module " << submodp->getId() << " to interfacTable[" << node << "]" << endl;
                node++;
            }
        }

        extEV << "Registered " << node << " nodes to interfaceTable size " << interfaceTable.size() << endl;

    }
    if (stage == 2){

        rtScheduler->setupandwait();

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
        handleIDB(msg);
        //cancelAndDelete(msg);
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

void IEEE802154ExtInterface::handleIDB(cMessage *msg)
{
    IDB *idb = check_and_cast<IDB *>(msg);

    if (interfaces < (int)interfaceTable.size()) {
        if (idb->getLinktype() == DLT_USER0) {
            extEV << simulation.getModule(interfaceTable[interfaces]) << " registered with Linktype " << idb->getLinktype() << endl;
        }
    } else {
        extEV << "Extern Node " << interfaces << " with Linktype " << idb->getLinktype() << " does not exist in simulation!" << endl;
    }

    interfaces++;

    cancelAndDelete(msg);
}

void IEEE802154ExtInterface::handleEPB(cMessage *msg)
{
    unsigned char rtBuffer[1<<16];

    EPB *epb = check_and_cast<EPB *>(msg);
    for (uint8_t i=0; i<epb->getDataArraySize(); i++) {
        rtBuffer[i] = epb->getData(i);
    }

    extEV << "Recv message from externNodes[" << epb->getInterface() << "]" << endl;

    Buffer b(rtBuffer, epb->getDataArraySize());

    // Message from external interface
    cMessage *sdu;
    sdu = serializer->deserializeSDU(b);
//      mpdu *pdu=check_and_cast<mpdu *>(serializer->deserialize(b));

    // corresponding module
    cModule *mod = simulation.getModule(interfaceTable[epb->getInterface()]);
    cModule *phy = mod->getSubmodule("NIC")->getSubmodule("PHY");

    this->sendDirect(sdu, phy, "inFromExt");
//    this->sendDirect(pdu, phy, "inFromExt");
    this->numRcvd++;

    cancelAndDelete(msg);
}

void IEEE802154ExtInterface::handleMsgSim(cMessage *msg)
{
    unsigned char mybuf[128+32+3];

    int module_id = msg->getSenderModule()->getParentModule()->getParentModule()->getId();
    int interface_id = -1;

    for (unsigned int i=0; i < interfaceTable.size(); i++){
        if (interfaceTable.at(i) == module_id){
            interface_id = i;
        }
    }

    if (interface_id == -1){
        EV_ERROR << "from Module " << msg->getSenderModule()->getParentModule()->getParentModule()->getName() << " Module_id is not in interfaceTable matching Interface_ID.\n Maybe are in wrong getParentModule()? should be Host" << endl;
    }

    Buffer buf(mybuf, 128+32+3);
    //serializer->serialize(mpdu_pkt, buf);
    serializer->serializeSDU(msg, buf);

    rtScheduler->sendEPB(interface_id, msg->getArrivalTime(), buf);

    extEV << "Send message from " << msg->getSenderModule()->getParentModule()->getParentModule()->getName() << "["<<interface_id<<"]" << endl;

    this->numSent++;

    cancelAndDelete(msg);
}
