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

    //zaehler = 0;
    //pdu = nullptr;

    s = new IEEE802154Serializer();

    remainingPayloadBytes = 0;
    recvPos = 0;
    //global_pcap_hdr.linktype = 0;
    //globalPcapReaded = false;
    BytesLeft = 0;

   // addr = par("addr");
   // srvAddr = par("srvAddr");

    //pcapng
    r = new PCAPNGReader(recvBuffer, 65536);

    numSent = numRcvd = numDropped = 0;

        WATCH(numSent);
        WATCH(numRcvd);
        WATCH(numDropped);
        WATCH(numRecvBytes);
        //WATCH(zaehler);
        WATCH(recvPos);
        //WATCH(globalPcapReaded);
        //WATCH(global_pcap_hdr.linktype);
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
        EV << "map: Interface_ID=0:ModuleID= " << interfaceTable[0]
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
    EV << "[ExtInterface]: msg arrive " << std::string(msg->getName()) << endl;
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
        EV << "processed until: " << recvPos << endl;
    }
    else if (std::string(msg->getName()) == "IDB Event"){
        EV << "handle Interface Data" << endl;
        r->peekBlock(curr_block, recvPos);
        recvPos += curr_block.total_length;
        EV << "processed until: " << recvPos << endl;

        EV << getParentModule()->getSubmodule("extClient") << std::endl; //found extInterface can acces via cModule: getId(), Name
    }
    else if (std::string(msg->getName()) == "EPB Event"){
        EV << "handle Enhanced Packet Data" << endl;

        handleEPB(msg);
    }
    else if (msg == rtEvent){  //obsolet
       EV << "Event from extern" << endl;
    }
    else {
        // received pkt to external Device(s)
        if (msg->arrivedOn("inDirect")){

            if (std::string(msg->getName()) == "PLME-CCA.request") {                      //ccaRequ == CCA
                EV << "PLME-CCA.request" << endl;
            } else if (std::string(msg->getName()) == "PLME-SET-TRX-STATE.request") {
                EV << "PLME-SET-TRX-STATE.request" << endl;
            } else if (std::string(msg->getName()) == "SET") {
                EV << "SET" << endl;
            } else if (std::string(msg->getName()) == "GET") {
                EV << "GET" << endl;
            } else if (std::string(msg->getName()) == "edRequ") {                //edRequ == ED
                EV << "ED" << endl;
            } else if (std::string(msg->getName()) == "PD-DATA"){
                EV << "msg classname: " << msg->getClassName() << endl;
                if (dynamic_cast<ppdu *>(msg) != NULL){
                    ppdu *pdu = check_and_cast<ppdu*>(msg);
                    EV << "pkt name: " << std::string(pdu->getName()) << " has encapsulated: " << pdu->hasEncapsulatedPacket() << endl;
                    if (pdu->hasEncapsulatedPacket()){
                        handleReply(msg);
                    }
                }

            }
            else {
              // PD <-> mpdu
              //handleReply(check_and_cast<PlainPkt *>(msg));
              //  handleReply(msg);
                EV << "msg classname: " << msg->getClassName() << endl;
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

    EV << "Packet in EPB begins: " << pos << " with length of: " << caplen
       << " from Interface_ID: " << interfaceid << endl;

    r->peekBlock(curr_block, recvPos);
    recvPos += curr_block.total_length;
    EV << "processed until: " << recvPos << endl;

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
    /*else if (c.errorOccured) {
        EV_ERROR << "Error with deserialize Frame with Context" << endl;
    }*/
    this->showFrameContent(frame);

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


    EV << getParentModule()->getSubmodule("extClient") << std::endl; //found extInterface can acces via cModule: getId(), Name, works
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



void IEEE802154ExtInterface::handleReply(cMessage *msg){

        ppdu * pkt = check_and_cast<ppdu *>(msg);
        mpdu * test = check_and_cast<mpdu *>(pkt->getEncapsulatedPacket());

        //unsigned int len = pkt->getCaplen();
        unsigned int len = pkt->getByteLength();
        unsigned char mybuf[128+32];

        //TODO: estiamte interface_id
        int module_id = msg->getSenderModule()->getParentModule()->getParentModule()->getId();
        int interface_id = -1;

        EV << "from module_ID:" << module_id << endl;
        for (unsigned int i=0; i < interfaceTable.size(); i++){
            EV << "interfaceTable["<<i<<"]="<<interfaceTable.at(i) << endl;
            if (interfaceTable.at(i) == module_id){
                interface_id = i;
            }
        }
        if (interface_id == -1){
            EV_ERROR << "from Module " << msg->getSenderModule()->getParentModule()->getParentModule()->getName() << " Module_id is not in interfaceTable matching Interface_ID.\n Maybe are in wrong getParentModule()? should be Host" << endl;
        }

        EV << "interface_id: " << interface_id << " from Module: " << msg->getSenderModule()->getParentModule()->getParentModule()->getName() << "["<<interface_id<<"] = " << module_id << endl;

        block_header blk;
        enhanced_packet_block epb;
        //Enhanced Packet Block, hardcoded all proprietary
        mybuf[0] = 0x06;  //blk_type
        mybuf[1] = 0x00;
        mybuf[2] = 0x00;
        mybuf[3] = 0x00;
        mybuf[4] = len + 32;  // blk_total_length
        mybuf[5] = 0x00;
        mybuf[6] = 0x00;
        mybuf[7] = 0x00;
        mybuf[8] = interface_id;  //interface_id
        mybuf[9] = 0x00;
        mybuf[10] = 0x00;
        mybuf[11] = 0x00;

        mybuf[12] = 0x00;  // timestamp high
        mybuf[13] = 0x00;
        mybuf[14] = 0x00;
        mybuf[15] = 0x00;
        mybuf[16] = 0x00;  // timestamp low
        mybuf[17] = 0x00;
        mybuf[18] = 0x00;
        mybuf[19] = 0x00;

        mybuf[20] = len;  // caplength
        mybuf[21] = 0x00;
        mybuf[22] = 0x00;
        mybuf[23] = 0x00;

        mybuf[24] = len;  // length
        mybuf[25] = 0x00;
        mybuf[26] = 0x00;
        mybuf[27] = 0x00;

        Buffer buf(mybuf, len+32);  // packet length + {minimum EPB size}:= 32
        //Context c;
        buf.seek(28);


        IEEE802154Serializer().serialize(test, buf);

        int trailer = len+28;
        mybuf[trailer] = len + 32;  // blk_total_length
        mybuf[trailer+1] = 0x00;
        mybuf[trailer+2] = 0x00;
        mybuf[trailer+3] = 0x00;

        unsigned char * ptr = mybuf;


/******************* Test *************************/
    Buffer b(ptr, len + 32);
    mpdu *frame;
    frame = check_and_cast<mpdu *>((IEEE802154Serializer().deserialize(b)));
    EV << "Frame deserialized as: " << frame->getClassName() << endl;
    //check if error
    if (b.hasError()) {
        EV_ERROR << "Error deserialize Frame with Buffer. Buffer pos: "
                        << b.getPos() << " and remaingByte size: "
                        << b.getRemainingSize() << endl;
    }
    this->showFrameContent(frame);
/******************* Test *************************/
        //EV << "EPB with interface_id: " << interface_id << endl;
        //rtScheduler->sendBytes(ptr ,static_cast<size_t>(len+32)); TODO: with Socket connect
        this->numSent++;
        delete pkt;

}

/*
 * move Buffer index and read Data from Buffer, store the Data in places: frame_hdrs and queue_pdu
 */
/*
void IEEE802154ExtInterface::processFrameAndSend()
{
   //handleHdr();
   //handleFrame();

    // assemble and send
    PlainPkt *pkt = new PlainPkt();
    pkt->encapsulate(queue_pdu.back()->getFrame());
    pkt->addByteLength(this->frame_hdrs.back().caplen);   //TODO: whole length or numBytesleft or both?
    //pkt->setPayload(header.c_str());
    pkt->setDestAddress(srvAddr);
    pkt->setSrcAddress(addr);

    send(pkt, "g$o");
}
*/
/**********************************************************/


// PCAPNG related
void IEEE802154ExtInterface::showFrameContent(mpdu *mp)
{
    EV << "\nIeee802154 Frame Content" <<endl;
    EV << "Frame Name: " << mp->getName() << " " << mp->getClassName() << endl;
    EV << "Bytelength: " << std::hex << mp->getByteLength() << endl;
    EV << "Dest PANID: " << mp->getDestPANid() << endl;

    //TODO: if both are 0 ?
    if (mp->getDest().isUnspecified()){
        EV << "Frame dest: " << mp->getDest().getShortAddr() << endl;
    } else {
        EV << "Frame dest: " << mp->getDest() << endl;
    }

    EV << "Src  PANID: " << mp->getSrcPANid() << endl;

    if (mp->getSrc().isUnspecified()){
        EV << "Frame src : " << mp->getSrc().getShortAddr() << endl;
    } else {
        EV << "Frame src : " << mp->getSrc() << endl;
    }

    EV << "Frame seqn: " << (mp->getSqnr() & 0xFF) << std::dec << endl;

    //TODO:  switch(Typ) case ......: EV case ...: EV
}


