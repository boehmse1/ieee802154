#include <PCAPRTScheduler.h>

#if OMNETPP_BUILDNUM <= 1003
#define FES(sim) (&sim->msgQueue)
#else
#define FES(sim) (sim->getFES())
#endif


Register_Class(PCAPRTScheduler);

Register_GlobalConfigOption(CFGID_SOCKETRTSCHEDULER_PORT, "socketrtscheduler-port", CFG_INT, "4242", "When PCAPRTScheduler is selected as scheduler class: the port number PCAPRTScheduler listens on.");

inline std::ostream& operator<<(std::ostream& out, const timeval& tv)
{
    return out << (unsigned long)tv.tv_sec << "s" << tv.tv_usec << "us";
}

PCAPRTScheduler::PCAPRTScheduler() : cRealTimeScheduler()
{
    listenerSocket = INVALID_SOCKET;
    connSocket = INVALID_SOCKET;

    globalPcapReaded = false;
    localPcapReaded = false;
    localPcapPktReaded = false;
    arrived = 0;
    nextFramePos = 0;
    count = 0;

    SHBMagicReaded = false;
    IDBReaded = false;
    idb_counter = 0;

}

PCAPRTScheduler::~PCAPRTScheduler()
{
}

std::string PCAPRTScheduler::info() const
{
    return "RealTime Scheduler based on PCAPNG over TCP-Socket";
}


void PCAPRTScheduler::startRun()
{
    if (initsocketlibonce() != 0)
        throw cRuntimeError("PCAPRTScheduler: Cannot initialize socket library");

    gettimeofday(&baseTime, nullptr);

    module = nullptr;
    notificationMsg = nullptr;
    this->waitforBytes = new cMessage("waitForBytes");
    pktHdrMsg = new cMessage("pktHdrMsg");
    //this->IDBMSGEvent = new cMessage("IDB Event");
    //this->EPBMSGEvent = new cMessage("EPB Event");
    recvBuffer = nullptr;
    recvBufferSize = 0;
    numBytesPtr = nullptr;

    port = this->sim->getEnvir()->getConfig()->getAsInt(CFGID_SOCKETRTSCHEDULER_PORT);
    //port = getEnvir()->getConfig()->getAsInt(CFGID_SOCKETRTSCHEDULER_PORT);
    setupListener();
}

void PCAPRTScheduler::setupListener()
{
    listenerSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenerSocket == INVALID_SOCKET)
        throw cRuntimeError("PCAPRTScheduler: cannot create socket");

    sockaddr_in sinInterface;
    sinInterface.sin_family = AF_INET;
    sinInterface.sin_addr.s_addr = INADDR_ANY;
    sinInterface.sin_port = htons(port);
    if (bind(listenerSocket, (sockaddr *) &sinInterface, sizeof(sockaddr_in)) == SOCKET_ERROR)
        throw cRuntimeError("PCAPRTScheduler: socket bind() failed");

    listen(listenerSocket, SOMAXCONN); /* SOMAXCONN: Maximum queue length specifiable by listen.  */
}

void PCAPRTScheduler::endRun()
{
    std::cout << "end run" << endl;
}

void PCAPRTScheduler::executionResumed()
{
    gettimeofday(&baseTime, nullptr);
    baseTime = timeval_substract(baseTime, SIMTIME_DBL(simTime()));
}

void PCAPRTScheduler::setInterfaceModule(cModule *mod, cMessage *notifMsg, cMessage *initMsg, unsigned char *buf, int bufSize, int *nBytesPtr)
{
    if (module){
        throw cRuntimeError("PCAPRTScheduler: setInterfaceModule() already called");
    }
    if (!mod || !notifMsg || !buf || !bufSize || !nBytesPtr){
        throw cRuntimeError("PCAPRTScheduler: setInterfaceModule(): arguments must be non-nullptr");
    }

    module = mod;
    notificationMsg = notifMsg;
    this->initMsg = initMsg;
    recvBuffer = buf;
    recvBufferSize = bufSize;
    numBytesPtr = nBytesPtr;
    *numBytesPtr = 0;

    r = new PCAPNGReader(buf, bufSize);
}


bool PCAPRTScheduler::receiveWithTimeout(long usec)
{
    std::cout << "amount of Bytes in Buffer: " << *numBytesPtr << " "<< nextFramePos << " received new Bytes: " << nBytes << std::endl;

    // prepare sets for select()
    fd_set readFDs, writeFDs, exceptFDs;
    FD_ZERO(&readFDs);
    FD_ZERO(&writeFDs);
    FD_ZERO(&exceptFDs);

    // if we're connected, watch connSocket, otherwise accept new connections
    if (connSocket != INVALID_SOCKET)
        FD_SET(connSocket, &readFDs);
    else
        FD_SET(listenerSocket, &readFDs);

    timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = usec;

    if (select(FD_SETSIZE, &readFDs, &writeFDs, &exceptFDs, &timeout) > 0) {
        // Something happened on one of the sockets -- handle them
        if (connSocket != INVALID_SOCKET && FD_ISSET(connSocket, &readFDs)) {
            // receive from connSocket
            unsigned char *bufPtr = recvBuffer + (*numBytesPtr);
            int bufLeft = recvBufferSize - (*numBytesPtr);
            if (bufLeft <= 0)
                throw cRuntimeError("PCAPRTScheduler: interface module's recvBuffer is full");  //FIXME: do Ringbuffer
            nBytes = recv(connSocket, bufPtr, bufLeft, 0);
            if (nBytes == SOCKET_ERROR) {
                rtEV << "socket error " << sock_errno() << "\n";
                closesocket(connSocket);
                connSocket = INVALID_SOCKET;
            }
            else if (nBytes == 0) {
                rtEV << "socket closed by the client\n";
                if (shutdown(connSocket, SHUT_WR) == SOCKET_ERROR)
                    throw cRuntimeError("PCAPRTScheduler: shutdown() failed");
                closesocket(connSocket);
                connSocket = INVALID_SOCKET;
            }
            //nBytes > 0
            else {
                // schedule notificationMsg for the interface module
                rtEV << "received " << nBytes << " bytes\n";
                (*numBytesPtr) += nBytes;

                std::cout << "PCAPRTScheduler: received " << nBytes << " bytes\n";

               // handleFragments() for dummy events
               if ((*numBytesPtr-nextFramePos) <= 8){
                   handleFragments();
               } else {
                   //more than 8 Bytes arrived check Block_Trailer
                   r->peekBlock(curr_block, nextFramePos);

                   //bytes are missing, we not already received complete packet
                   if (! ((*numBytesPtr-nextFramePos) >= curr_block.total_length)){
                          handleFragments();
                   }

                   //TODO: if while(...) will not succed than else
                   // handle Block content
                   while((*numBytesPtr-nextFramePos) >= curr_block.total_length)
                   {
                       std::cout << "PCAPRTScheduler: currentBytes: " << (*numBytesPtr-nextFramePos) << " len: " << curr_block.total_length << std::endl;
                       r->peekBlock(curr_block, nextFramePos);
                       std::cout << "PCAPRTScheduler: peekBlock: " << curr_block.block_type << std::endl;
                       handleBlock();
                   }

               }//else


                return true;  //yes there was an Event
            }
        }
        else if (FD_ISSET(listenerSocket, &readFDs)) {
            // accept connection, and store FD in connSocket
            sockaddr_in sinRemote;
            int addrSize = sizeof(sinRemote);
            connSocket = accept(listenerSocket, (sockaddr *) &sinRemote, (socklen_t *) &addrSize);
            if (connSocket == INVALID_SOCKET)
                throw cRuntimeError("PCAPRTScheduler: accept() failed");
            rtEV << "PCAPRTScheduler: connected!\n";
        }
    }
    return false;
}

int PCAPRTScheduler::receiveUntil(const timeval& targetTime)
{
    // if there's more than 200ms to wait, wait in 100ms chunks
    // in order to keep UI responsiveness by invoking ev.idle()
    timeval curTime;
    gettimeofday(&curTime, NULL);
    while (targetTime.tv_sec - curTime.tv_sec >= 2
            || timeval_diff_usec(targetTime, curTime) >= 200000) {
        if (receiveWithTimeout(100000)) // 100ms
            return 1;
        if (ev.idle())
            return -1;
        gettimeofday(&curTime, NULL);
    }

    // difference is now at most 100ms, do it at once
    long usec = timeval_diff_usec(targetTime, curTime);
    if (usec > 0)
        if (receiveWithTimeout(usec))
            return 1;
    return 0;
}

//if OMNETPP_VERSION >= 0x500 ...
/*
cMessage *PCAPRTScheduler::guessNextEvent()
{
    return sim->getFES()->peekFirst();
}
*/

cMessage *PCAPRTScheduler::getNextEvent()
{
    // assert that we've been configured
    if (!module)
        throw cRuntimeError(
                "PCAPRTScheduler: setInterfaceModule() not called: it must be called from a module's initialize() function");

    // calculate target time
    timeval targetTime;
    cMessage *msg = sim->msgQueue.peekFirst();
    if (!msg) {
        // if there are no events, wait until something comes from outside
        // TBD: obey simtimelimit, cpu-time-limit
        targetTime.tv_sec = LONG_MAX;
        targetTime.tv_usec = 0;
    } else {
        // use time of next event
        simtime_t eventSimtime = msg->getArrivalTime();
        targetTime = timeval_add(baseTime, SIMTIME_DBL(eventSimtime));
    }

    // if needed, wait until that time arrives
    timeval curTime;
    gettimeofday(&curTime, NULL);
    if (timeval_greater(targetTime, curTime)) {
        int status = receiveUntil(targetTime);
        if (status == -1)
            return NULL; // interrupted by user
        if (status == 1)
            msg = sim->msgQueue.peekFirst(); // received something
    } else {
        // we're behind -- customized versions of this class may
        // alert if we're too much behind, whatever that means
    }

    // ok, return the message
    return msg;
}

/*
void PCAPRTScheduler::putBackEvent(cMessage *event)
{
    sim->getFES()->putBackFirst(event);
}
*/

void PCAPRTScheduler::sendEPB(int interface, simtime_t_cref time, Buffer &b)
{
    block_header header;
    enhanced_packet_block packet;
    block_trailer trailer;

    unsigned short len = b.getPos();
    uint8_t padding;
    uint8_t pad[] = {0,0,0,0};

    if (len%4) padding = 4 - (len%4);
    else padding = 0;

    header.block_type = BT_EPB;
    header.total_length = sizeof(header) + sizeof(packet) + len + padding + sizeof(trailer);

    packet.interface_id = interface;
    packet.timestamp_high = (time.raw() - (time.raw() % time.getScale())) / time.getScale();
    //packet.timestamp_high = time.inUnit(0);
    packet.timestamp_low = 1000000 * (time.raw() % time.getScale()) / time.getScale();
    //packet.timestamp_low = time.inUnit(-3);
    packet.caplen = len;
    packet.len = len;

    trailer.total_length = header.total_length;

    uint8_t *sendBuf = (uint8_t*)malloc(header.total_length);
    memcpy(sendBuf, &header, sizeof(header));
    memcpy(sendBuf+sizeof(header), &packet, sizeof(packet));
    memcpy(sendBuf+sizeof(header)+sizeof(packet), b._getBuf(), len);
    memcpy(sendBuf+sizeof(header)+sizeof(packet)+len, &pad, padding);
    memcpy(sendBuf+sizeof(header)+sizeof(packet)+len+padding, &trailer, sizeof(trailer));

    sendBytes(sendBuf, header.total_length);
}

void PCAPRTScheduler::sendBytes(unsigned char *buf, size_t numBytes)
{
    if (connSocket == INVALID_SOCKET)
            throw cRuntimeError("PCAPRTScheduler: sendBytes(): no connection");

    int transmitted = send(connSocket, buf, numBytes, 0);

    free(buf);

    if ((size_t) transmitted == numBytes)
        rtEV << "sendBytes(): send with length " << transmitted << endl;
    else
        rtEV << "sendBytes(): send with length " << numBytes << " failed. Sendbytes: " << transmitted << endl;
}

void PCAPRTScheduler::checkPacket(uint16_t LinkType)
{
    switch(LinkType)
    {
    case DLT_IEEE802_15_4_NOFCS:
        rtEV << "LinkType is: DLT_IEEE802_15_4_NOFCS" << endl; //TODO: verify that no FCS at the end of 1. Frame
        break;
    case DLT_IEEE802_15_4:
        rtEV << "LinkType is: DLT_IEEE802_15_4" << endl;       //TODO: handle FCS, is not enabled in serializer! //FIXME:
        break;
    case DLT_IEEE802_15_4_NONASK_PHY:
        rtEV << "LinkType is: DLT_IEEE802_15_4_NONASK_PHY" << endl;  // not handled
        break;
    default:
        rtEV << "unknown LinkType Number: " << LinkType << endl;
    }
}

// Bytes received but not enough for evaluate a Block
void PCAPRTScheduler::handleFragments()
{
    timeval curTime;
    gettimeofday(&curTime, nullptr);
    curTime = timeval_substract(curTime, baseTime);
    simtime_t t = curTime.tv_sec + curTime.tv_usec * 1e-6;
    // TBD assert that it's somehow not smaller than previous event's time
    waitforBytes->setArrival(module, -1, t);

    simulation.msgQueue.insert(waitforBytes);
    //Generates dummy Event for FES to consume for ExtInterface,
    //without this the simulation would "think" there are nothing more to do and stop the simulation
}

void PCAPRTScheduler::handleFileHdr()
{
    // solution
    // if (*numBytesPtr >= 12 Byte) at least the Field: Block Total Length arrived ... calc Block length
    if (*numBytesPtr >= 8 and SHBMagicReaded == false) {
        if (MAGIC_NUMBER_SHB == read4Bytes(recvBuffer, 0)) {
            r->openBlock();
            this->nextFrameLength = r->getBlockLength();
            //SHBMagicReaded = true;   // r->getCurrentBlockHeader().block_type should 0x0A0D0D0A
            //normalerweise cool und richtig, Probleme der Nebenläufigkeit erfordern andere Maßnahmen

            timeval curTime;
            gettimeofday(&curTime, nullptr);
            curTime = timeval_substract(curTime, baseTime);
            simtime_t t = curTime.tv_sec + curTime.tv_usec * 1e-6;
            // TBD assert that it's somehow not smaller than previous event's time
            initMsg->setArrival(module, -1, t);
            simulation.msgQueue.insert(initMsg);
        }
    }
}

void PCAPRTScheduler::handleSHB()
{
    std::cout << "PCAPRTScheduler: handle SHB" << std::endl;
    std::cout << "PCAPRTScheduler: nextFrameLength " << nextFrameLength << std::endl;
    std::cout << "PCAPRTScheduler: nextFramePos " << nextFramePos << std::endl;
    if ((unsigned) *numBytesPtr >= nextFrameLength) {
        r->openSectionHeader();
        //SHBMagicReaded = r->getMagicReaded();  //FIXME:
        //nextFramePos = IDB Block, next Block after SHB

        timeval curTime;
        gettimeofday(&curTime, nullptr);
        curTime = timeval_substract(curTime, baseTime);
        simtime_t t = curTime.tv_sec + curTime.tv_usec * 1e-6;
        // TBD assert that it's somehow not smaller than previous event's time
        pktHdrMsg->setArrival(module, -1, t);
        simulation.msgQueue.insert(pktHdrMsg);

        SHBMagicReaded = true;
    }
}

void PCAPRTScheduler::handleIDB()
{
    //if (SHBMagicReaded == true){  //FIXME: shbmagicreaded flag
      r->openBlock();

      this->nextFrameLength = r->getBlockLength();
      std::cout << "PCAPRTScheduler: nextFrameLength " << nextFrameLength << std::endl;

      if ((unsigned)*numBytesPtr >= nextFrameLength)
      {
        r->openInterfaceDescription();
        unsigned char * euiaddr = r->getEUIAddr();

        //to, from
        memcpy(euiaddr, r->getEUIAddr(), (size_t) 8);

        std::cout << "PCAPRTScheduler: euiaddr: " << euiaddr << std::endl;

        timeval curTime;
        gettimeofday(&curTime, nullptr);
        curTime = timeval_substract(curTime, baseTime);
        simtime_t t = curTime.tv_sec + curTime.tv_usec * 1e-6;
        // TBD assert that it's somehow not smaller than previous event's time

        // single IDB solution
        //IDBMSGEvent->setArrival(module->getId(), -1, t);
        //getSimulation()->getFES()->insert(IDBMSGEvent);

        rtEV << "IDB arrived with LinkType: " << r->getLinkType() << endl;
        // vector solution
        cMessage *neu = new cMessage("IDB Event");
        neu->setArrival(module, -1, t);
        IDBMSGEvent.push_back(neu);
        simulation.msgQueue.insert(IDBMSGEvent.back());

        IDBReaded = true;
        idb_counter++;
      }
    //}
}

void PCAPRTScheduler::handleEPB()
{
    std::cout << "PCAPRTScheduler: SHBMagicReaded: " << SHBMagicReaded << " IDBReaded: " << IDBReaded << std::endl;
    if (SHBMagicReaded and IDBReaded){
      r->openBlock();
      this->nextFrameLength = r->getBlockLength();
      std::cout << "PCAPRTScheduler: nextFrameLength " << nextFrameLength << std::endl;
      if ((unsigned)*numBytesPtr >= nextFrameLength)
      {
        r->openEnhancedPacketBlock();


        // schedule EPB als Message in FES
        timeval curTime;
        gettimeofday(&curTime, nullptr);
        curTime = timeval_substract(curTime, baseTime);
        simtime_t t = curTime.tv_sec + curTime.tv_usec * 1e-6;
        // TBD assert that it's somehow not smaller than previous event's time

        enhanced_packet_block tmp = r->getEPB();
        std::cout << "PCAPRTScheduler: caplen: " << tmp.caplen << " interface_id: " << tmp.interface_id << std::endl;

            //packet
//            unsigned char *data;
//            r->getPacket(data);
//            for (int i=0; i < tmp.caplen; i++){
//                std::cout << std::hex << data[i] << " ";
//            }
//            std::cout << std::dec << std::endl;

        PlainPkt *pkt = new PlainPkt("EPB Event");
        pkt->setByteLength(tmp.caplen);
        pkt->setCaplen(tmp.caplen);
        pkt->setInterface_id(tmp.interface_id);
        pkt->setDestAddress(tmp.interface_id);
        pkt->setSrcAddress(-1);
        pkt->setPos(r->getPacketBegin()); // from that Position at Buffer the pkt begins

        pkt->setArrival(module, -1, t);
        EPBMSGEvent.push_back(pkt);
        simulation.msgQueue.insert(EPBMSGEvent.back());
      }
    }
}

void PCAPRTScheduler::handleBlock()
{

    switch (curr_block.block_type){
        case BT_SHB:
            handleFileHdr();
            handleSHB();
            nextFramePos += curr_block.total_length;
            std::cout << "PCAPRTScheduler: nextFramePos: " << nextFramePos << std::endl;
            break;
        case BT_IDB:
            handleIDB();
            nextFramePos += curr_block.total_length;
            std::cout << "PCAPRTScheduler: nextFramePos: " << nextFramePos << std::endl;
            break;
        case BT_EPB:
            handleEPB();
            nextFramePos += curr_block.total_length;
            std::cout << "PCAPRTScheduler: nextFramePos: " << nextFramePos << std::endl;
            break;
        case BT_SPB: //handleSPB();
            break;
        default: {
          rtEV << "Not supported Block recognized, next Data is garbage. You need to skip it manually" << endl;
        }
    }
}

bool PCAPRTScheduler::waitForBlock()
{
   // if not all Bytes for this Block arrives, simply wait
   if ((unsigned int)*numBytesPtr >= curr_block.total_length)
   {
       return false; //needs not to wait, all Bytes are present
   } else {
       return true; //needs to wait
   }
}
