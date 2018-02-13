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
    delete(r);
    delete(s);
}

void IEEE802154ExtInterface::initialize(int stage)
{
    cSimpleModule::initialize(stage);
    if (stage == 0)
    {
    rtEvent = new cMessage("rtEvent");
    initEvent = new cMessage("SHB_Event");
    rtScheduler = check_and_cast<PCAPRTScheduler *>(simulation.getScheduler());
    rtScheduler->setInterfaceModule(this, rtEvent, initEvent, recvBuffer, 65536, &numRecvBytes);

    s = new IEEE802154Serializer();

    remainingPayloadBytes = 0;
    recvPos = 0;
    BytesLeft = 0;

    r = new PCAPNGReader(recvBuffer, 65536);

    numSent = numRcvd = numDropped = 0;

        WATCH(numSent);
        WATCH(numRcvd);
        WATCH(numDropped);
        WATCH(numRecvBytes);
        WATCH(recvPos);
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
  //count sth and EV it
}

void IEEE802154ExtInterface::handleMessage(cMessage *msg)
{
    extEV << "[ExtInterface]: msg arrive " << std::string(msg->getName()) << endl;
    if (msg == initEvent){
        //handlePcapFileHeader();
        //FileHeader arrived
    }
    else if(std::string(msg->getName()) == "waitForBytes"){
       //std::cout << "time elapsed: " << getSimulation()->getSimTime().str() << " sec."<< endl;
       std::cout << "time elapsed: " << simulation.getSimTime().str() << " sec." << endl;
    }
    else if(std::string(msg->getName()) == "pktHdrMsg"){
       //handleHdr();
        r->peekBlock(curr_block, recvPos);
        recvPos += curr_block.total_length;
        extEV << "processed until: " << recvPos << endl;
    }
    else if (std::string(msg->getName()) == "IDB Event"){
        extEV << "handle Interface Data" << endl;
        r->peekBlock(curr_block, recvPos);
        recvPos += curr_block.total_length;
        extEV << "processed until: " << recvPos << endl;

        extEV << getParentModule()->getSubmodule("extClient") << std::endl; //found extInterface can acces via cModule: getId(), Name
    }
    else if (std::string(msg->getName()) == "EPB Event"){
        extEV << "handle Enhanced Packet Data" << endl;

        handleEPB(msg);
    }
    else if (msg == rtEvent){  //obsolet
        extEV << "Event from extern" << endl;
    }
    else {
        // received pkt to external Device(s)
        if (msg->arrivedOn("inDirect")){

            if (std::string(msg->getName()) == "PLME-CCA.request") {                      //ccaRequ == CCA
                extEV << "PLME-CCA.request" << endl;
            } else if (std::string(msg->getName()) == "PLME-SET-TRX-STATE.request") {
                extEV << "PLME-SET-TRX-STATE.request" << endl;
            } else if (std::string(msg->getName()) == "SET") {
                extEV << "SET" << endl;
            } else if (std::string(msg->getName()) == "GET") {
                extEV << "GET" << endl;
            } else if (std::string(msg->getName()) == "edRequ") {                //edRequ == ED
                extEV << "ED" << endl;
            } else if (std::string(msg->getName()) == "PD-DATA"){
                extEV << "msg classname: " << msg->getClassName() << endl;
                if (dynamic_cast<ppdu *>(msg) != NULL){
                    ppdu *pdu = check_and_cast<ppdu*>(msg);
                    extEV << "pkt name: " << std::string(pdu->getName()) << " has encapsulated: " << pdu->hasEncapsulatedPacket() << endl;
                    if (pdu->hasEncapsulatedPacket()){
                        handleReply(msg);
                    }
                }

            }
            else {
              // PD <-> mpdu
              //handleReply(check_and_cast<PlainPkt *>(msg));
              //  handleReply(msg);
                extEV << "msg classname: " << msg->getClassName() << endl;
            }
        }
    }

}

void IEEE802154ExtInterface::handleEPB(cMessage *msg)
{

    PlainPkt *plainMsg = check_and_cast<PlainPkt *>(msg);
    int clientAddr = plainMsg->getSrcAddress();
    int srvAddr = plainMsg->getDestAddress();
    unsigned int caplen = plainMsg->getCaplen();
    unsigned int pos = plainMsg->getPos();
    unsigned int interfaceid = plainMsg->getInterface_id();

    extEV << "Packet in EPB begins: " << pos << " with length of: " << caplen
       << " from Interface_ID: " << interfaceid << endl;

    r->peekBlock(curr_block, recvPos);
    recvPos += curr_block.total_length;
    extEV << "processed until: " << recvPos << endl;

    // de-serialize IEEE 802.15.4 to OMNeT++ Format
    Buffer b((recvBuffer + pos), caplen);
    //Context c;
    //c.throwOnSerializerNotFound = false;

    mpdu *frame;
    frame = check_and_cast<mpdu *>(
            (IEEE802154Serializer().deserialize(b)));
    std::cout << "Frame deserialized as: " << frame->getClassName()
            << std::endl;
    //check if error
    if (b.hasError()) {
        EV_ERROR << "Error deserialize Frame with Buffer. Buffer pos: "
                        << b.getPos() << " and remaingByte size: "
                        << b.getRemainingSize() << endl;
    }

    // send the mpdu in a NetPacket
    PlainPkt *pkt = new PlainPkt();
    pkt->setInterface_id(plainMsg->getInterface_id());      //external device_id
    pkt->setSrcAddress(this->getId());
    pkt->setDestAddress(srvAddr);
    //pkt->encapsulate(frame);
    //send(pkt, "g$o");

    //targetModule = getParentModule()->getSubmodule("IEEE802154Nodes[1]");  //IEEE802154ExtNodes              //error
    //targetModule = getParentModule()->getSubmodule("IEEE802154ExtNodes"); //test um alle Module zu erhalten, error
    //targetModule = simulation.getModuleByPath("SchedulerTest.IEEE802154Node[0].NIC.MAC.Buffer.inMLME"); // error
    //cModule *sim = simulation.getModule(1);
    // only for testing purpose


    extEV << getParentModule()->getSubmodule("extClient") << std::endl; //found extInterface can acces via cModule: getId(), Name, works
    cModule *mod = simulation.getModule(interfaceTable[interfaceid]);

    strstr << "SchedulerTest." << std::string(mod->getName()) << "[" << interfaceid << "]" << ".NIC.ExtPHY";
    std::string test = strstr.str();
    std::cout << test << std::endl;
    std::string s = (mod->getSubmodule("NIC")->getName());
    std::cout << s << std::endl;

    std::string s2 = (mod->getSubmodule("NIC")->getSubmodule("ExtPHY")->getName());
        std::cout << s2 << std::endl;

    cModule *mygate = mod->getSubmodule("NIC")->getSubmodule("ExtPHY");
    std::cout << "gatesize: " << mygate->getGateNames().size() << std::endl;
    std::cout << std::string(mygate->gate("inFromExt")->getName()) << std::endl;


    this->sendDirect(frame, mygate, "inFromExt");

    //delete(frame);

    //mod->getSubmodule("NIC")->getSubmodule("ExtPHY");  //will be terrible crash, each pointer can return NULL
    //mod->getModuleByPath("NIC.ExtPHY") nullpointer should be absolute path, mod->getName() +"NIC.ExtPHY";

    //TODO: get MACAdr from IDB Block, check mac

    //this->sendDirect() based on Interface ID and module id, TODO: configurations Parameter getPar
    // send MPDU to node
    //if (std::string(frame->getClassName()) == "CmdFrame"){
    //    this->sendDirect(frame, simulation.getModule(interfaceTable[interfaceid]), "inFromExt");  //"inMLME", hopefully works else IEEE802154ExtPHY ID Table...
    //}
    /*else {
        this->sendDirect(frame, simulation.getModule(interfaceTable[interfaceid]), "inMCPS");
    }*/

}

void IEEE802154ExtInterface::handleReply(cMessage *msg)
{
    extEV << "Send msg " << msg->getClassName() << " from intern simulation to external devices" << endl;
    unsigned char mybuf[128+32+3];

    int module_id = msg->getSenderModule()->getParentModule()->getParentModule()->getId();
    int interface_id = -1;

    for (unsigned int i=0; i < interfaceTable.size(); i++){
        extEV << "interfaceTable["<<i<<"]="<<interfaceTable.at(i) << endl;
        if (interfaceTable.at(i) == module_id){
            interface_id = i;
        }
    }

    if (interface_id == -1){
        EV_ERROR << "from Module " << msg->getSenderModule()->getParentModule()->getParentModule()->getName() << " Module_id is not in interfaceTable matching Interface_ID.\n Maybe are in wrong getParentModule()? should be Host" << endl;
    }

    extEV << "interface_id: " << interface_id << " from Module: " << msg->getSenderModule()->getParentModule()->getParentModule()->getName() << "["<<interface_id<<"] = " << module_id << endl;

    Buffer buf(mybuf, 128+32+3);
    //IEEE802154Serializer().serialize(mpdu_pkt, buf);
    IEEE802154Serializer().serializeSDU(msg, buf);

    rtScheduler->sendEPB(interface_id, msg->getArrivalTime(), buf);
    this->numSent++;

    cancelAndDelete(msg);
}
