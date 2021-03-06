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

    nextFramePos = 0;

    SHBReaded = false;
    IDBReaded = false;
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
    recvBuffer = nullptr;
    recvBufferSize = 0;
    numBytesPtr = nullptr;

    WATCH(recvBuffer);
    WATCH(recvBufferSize);

    port = this->sim->getEnvir()->getConfig()->getAsInt(CFGID_SOCKETRTSCHEDULER_PORT);
    //port = getEnvir()->getConfig()->getAsInt(CFGID_SOCKETRTSCHEDULER_PORT);

    // reuse connection immediately
    enableReuse = 1;

    setupListener();
    //connectSocket();

    if (FILEWRITE) {
        setupFilewrite();
    }
}

void PCAPRTScheduler::connectSocket()
{
    connSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (connSocket == INVALID_SOCKET)
        throw cRuntimeError("PCAPRTScheduler: cannot create socket");

    sockaddr_in sinInterface;
    sinInterface.sin_family = AF_INET;
    sinInterface.sin_addr.s_addr = INADDR_ANY;
    sinInterface.sin_port = htons(port);
    if (connect(connSocket,(sockaddr *) &sinInterface, sizeof(sockaddr_in)) < 0){
        throw cRuntimeError("PCAPRTScheduler: socket connect() failed");
    }
}

void PCAPRTScheduler::setupListener()
{
    listenerSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenerSocket == INVALID_SOCKET)
        throw cRuntimeError("PCAPRTScheduler: cannot create socket");

    if (setsockopt(listenerSocket, SOL_SOCKET, SO_REUSEADDR, &enableReuse, sizeof(int)) < 0)
        throw cRuntimeError("PCAPRTScheduler: socket setsockopt() failed");

    sockaddr_in sinInterface;
    sinInterface.sin_family = AF_INET;
    sinInterface.sin_addr.s_addr = INADDR_ANY;
    sinInterface.sin_port = htons(port);
    if (bind(listenerSocket, (sockaddr *) &sinInterface, sizeof(sockaddr_in)) == SOCKET_ERROR)
        throw cRuntimeError("PCAPRTScheduler: socket bind() failed");

    listen(listenerSocket, SOMAXCONN); /* SOMAXCONN: Maximum queue length specifiable by listen.  */
}

void PCAPRTScheduler::setupFilewrite()
{
    outputFile.open("schedulerLog.pcapng", ios::binary | ios::out);
}

void PCAPRTScheduler::endRun()
{
    rtEV << "end run" << endl;
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

    pcapng = new PCAPNGReader(buf, bufSize);
}


bool PCAPRTScheduler::receiveWithTimeout(long usec)
{
    //rtEV << "amount of Bytes in Buffer: " << *numBytesPtr << " "<< nextFramePos << " received new Bytes: " << nBytes << std::endl;

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
                throw cRuntimeError("interface module's recvBuffer is full");  //FIXME: do Ringbuffer
            nBytes = recv(connSocket, bufPtr, bufLeft, 0);
            if (nBytes == SOCKET_ERROR) {
                rtEV << "socket error " << sock_errno() << "\n";
                closesocket(connSocket);
                connSocket = INVALID_SOCKET;
            }
            else if (nBytes == 0) {
                rtEV << "socket closed by the client\n";
                if (shutdown(connSocket, SHUT_WR) == SOCKET_ERROR)
                    throw cRuntimeError("shutdown() failed");
                closesocket(connSocket);
                connSocket = INVALID_SOCKET;
            }
            //nBytes > 0
            else {
                // schedule notificationMsg for the interface module
                rtEV << "received " << nBytes << " bytes\n";
                (*numBytesPtr) += nBytes;

                // handleFragments() for dummy events
                if ((*numBytesPtr-nextFramePos) <= 8){
                    handleFragments();
                } else {
                    //more than 8 Bytes arrived check Block_Trailer
                    pcapng->peekBlock(curr_block, nextFramePos);

                    //bytes are missing, we not already received complete packet
                    if (! ((*numBytesPtr-nextFramePos) >= curr_block.total_length)){
                        handleFragments();
                    }

                    //TODO: if while(...) will not succed than else
                    // handle Block content
                    while((*numBytesPtr-nextFramePos) >= curr_block.total_length) {
                        rtEV << "currentBytes: " << (*numBytesPtr-nextFramePos) << " len: " << curr_block.total_length << std::endl;
                        pcapng->peekBlock(curr_block, nextFramePos);
                        handleBlock();
                    }

                } //else
                return true;  //yes there was an Event
            }
        }
        else if (FD_ISSET(listenerSocket, &readFDs)) {
            // accept connection, and store FD in connSocket
            sockaddr_in sinRemote;
            int addrSize = sizeof(sinRemote);
            connSocket = accept(listenerSocket, (sockaddr *) &sinRemote, (socklen_t *) &addrSize);
            if (connSocket == INVALID_SOCKET)
                throw cRuntimeError("PCAPRTScheduler: Socket accept() failed");

            rtEV << "Client connected on Port " << port << endl;

            //if (FILEWRITE) {
            //    sendSHB();
            //    sendIDB(DLT_USER0, 256);
            //    sendIDB(DLT_IEEE802_15_4_NOFCS, 256);
            //}
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

void PCAPRTScheduler::sendSHB()
{
    block_header header;
    section_header_block packet;
    block_trailer trailer;

    header.block_type = BT_SHB;
    header.total_length = sizeof(header) + sizeof(packet) + sizeof(trailer);

    packet.byte_order_magic = BYTE_ORDER_MAGIC;
    packet.major_version = PCAP_NG_VERSION_MAJOR;
    packet.minor_version = PCAP_NG_VERSION_MINOR;
    packet.section_length = -1;

    trailer.total_length = header.total_length;

    uint8_t *sendBuf = (uint8_t*)malloc(header.total_length);
    memcpy(sendBuf, &header, sizeof(header));
    memcpy(sendBuf+sizeof(header), &packet, sizeof(packet));
    memcpy(sendBuf+sizeof(header)+sizeof(packet), &trailer, sizeof(trailer));

    sendBytes(sendBuf, header.total_length);
}

void PCAPRTScheduler::sendIDB(int linktype, int snaplen)
{
    block_header header;
    interface_description_block packet;
    block_trailer trailer;

    header.block_type = BT_IDB;
    header.total_length = sizeof(header) + sizeof(packet) + sizeof(trailer);

    packet.linktype = linktype;
    packet.reserved = 0;
    packet.snaplen = snaplen;

    trailer.total_length = header.total_length;

    uint8_t *sendBuf = (uint8_t*)malloc(header.total_length);
    memcpy(sendBuf, &header, sizeof(header));
    memcpy(sendBuf+sizeof(header), &packet, sizeof(packet));
    memcpy(sendBuf+sizeof(header)+sizeof(packet), &trailer, sizeof(trailer));

    sendBytes(sendBuf, header.total_length);
}


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

    if (FILEWRITE) {
        outputFile.write((const char *)buf, numBytes);
        outputFile.flush();
        rtEV << "writeBytes(" << transmitted << ")" << endl;
    }

    free(buf);

    rtEV << "sendBytes(" << transmitted << ")" << endl;
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

void PCAPRTScheduler::handleFragments()
{
    timeval curTime;
    gettimeofday(&curTime, nullptr);
    curTime = timeval_substract(curTime, baseTime);
    simtime_t t = curTime.tv_sec + curTime.tv_usec * 1e-6;
    // TBD assert that it's somehow not smaller than previous event's time
    waitforBytes->setArrival(module, -1, t);

    // dummy Event for FES to consume for ExtInterface
    simulation.msgQueue.insert(waitforBytes);
}

void PCAPRTScheduler::handleSHB()
{
    if (*numBytesPtr >= 8 and SHBReaded == false) {
        if (BT_SHB == read4Bytes(recvBuffer, 0)) {
            pcapng->openBlock();

            this->nextFrameLength = pcapng->getBlockLength();
            //rtEV << "nextFrameLength " << nextFrameLength << std::endl;

            if ((unsigned) *numBytesPtr >= nextFrameLength) {
                pcapng->openSectionHeader();

                timeval curTime;
                gettimeofday(&curTime, nullptr);
                curTime = timeval_substract(curTime, baseTime);
                simtime_t t = curTime.tv_sec + curTime.tv_usec * 1e-6;
                // TBD assert that it's somehow not smaller than previous event's time

                initMsg->setArrival(module, -1, t);
                simulation.msgQueue.insert(initMsg);

                SHBReaded = true;
            }
        }
    }
}

void PCAPRTScheduler::handleIDB()
{
    if (SHBReaded == true) {
        pcapng->openBlock();

        this->nextFrameLength = pcapng->getBlockLength();
        //rtEV << "nextFrameLength " << nextFrameLength << std::endl;

        if ((unsigned)*numBytesPtr >= nextFrameLength) {
            pcapng->openInterfaceDescription();

            timeval curTime;
            gettimeofday(&curTime, nullptr);
            curTime = timeval_substract(curTime, baseTime);
            simtime_t t = curTime.tv_sec + curTime.tv_usec * 1e-6;
            // TBD assert that it's somehow not smaller than previous event's time

            IDB *idb = new IDB("IDB Event");
            idb->setLinktype(pcapng->getLinkType());

            idb->setArrival(module, -1, t);
            IDBMSGEvent.push_back(idb);
            simulation.msgQueue.insert(IDBMSGEvent.back());

            IDBReaded = true;
        }
    } else {
        rtEV << "SHBReaded: " << SHBReaded << std::endl;
    }
}

void PCAPRTScheduler::handleEPB()
{
    if (SHBReaded and IDBReaded) {
        pcapng->openBlock();

        this->nextFrameLength = pcapng->getBlockLength();
        //rtEV << "nextFrameLength " << nextFrameLength << std::endl;

        if ((unsigned)*numBytesPtr >= nextFrameLength) {
            pcapng->openEnhancedPacketBlock();

            // schedule EPB als Message in FES
            timeval curTime;
            gettimeofday(&curTime, nullptr);
            curTime = timeval_substract(curTime, baseTime);
            simtime_t t = curTime.tv_sec + curTime.tv_usec * 1e-6;
            // TBD assert that it's somehow not smaller than previous event's time

            unsigned char array[127];
            unsigned char *data;

            data = array;
            pcapng->getPacket(data);

            EPB *epb = new EPB("EPB Event");
            enhanced_packet_block tmp = pcapng->getEPB();
            epb->setCap_len(tmp.caplen);
            epb->setInterface(tmp.interface_id);

            for (uint8_t i=0; i<tmp.caplen; i++) {
                epb->setData(i, array[i]);
            }

            epb->setArrival(module, -1, t);
            EPBMSGEvent.push_back(epb);
            simulation.msgQueue.insert(EPBMSGEvent.back());
        }
    } else {
        rtEV << "SHBMagicReaded: " << SHBReaded << " IDBReaded: " << IDBReaded << std::endl;
    }
}

void PCAPRTScheduler::handleBlock()
{

    //rtEV << "handleBlock " << curr_block.block_type << std::endl;

    switch (curr_block.block_type){
        case BT_SHB:
            handleSHB();
            nextFramePos += curr_block.total_length;
            //rtEV << "nextFramePos: " << nextFramePos << std::endl;
            break;
        case BT_IDB:
            handleIDB();
            nextFramePos += curr_block.total_length;
            //rtEV << "nextFramePos: " << nextFramePos << std::endl;
            break;
        case BT_EPB:
            handleEPB();
            nextFramePos += curr_block.total_length;
            //rtEV << "nextFramePos: " << nextFramePos << std::endl;
            break;
        default:
            rtEV << "Not supported Block recognized, next Data is garbage. You need to skip it manually" << endl;
            break;
    }
}

bool PCAPRTScheduler::waitForBlock()
{
   // if not all Bytes for this Block arrives, simply wait
   if ((unsigned int)*numBytesPtr >= curr_block.total_length) {
       return false; //needs not to wait, all Bytes are present
   } else {
       return true; //needs to wait
   }
}
