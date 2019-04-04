//
// Copyright (C) 2018 Sebastian Boehm (BTU-CS)
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

#include "IEEE802154Serializer.h"
#include <arpa/inet.h>
#include "PPDU_m.h"

/*
 * cMessage SDU msg will be written into Buffer &b
 */
void IEEE802154Serializer::serializeSDU(cMessage *msg, Buffer &b)
{
    sEV << "Serialize message " << msg->getName() << " (Time: " << msg->getArrivalTime() << ")" << endl;


    if (msg->isPacket())
    {
        uint8_t mybuf[127];
        Buffer buf(mybuf, 127);
        ppdu * pkt = check_and_cast<ppdu *>(msg);
        serialize(pkt->getEncapsulatedPacket(), buf);
        b.writeByte(PD_DATA_REQUEST);
        b.writeByte(SIZEOF_PD_DATA_REQUEST+buf.getPos());
        b.writeByte(buf.getPos());
        b.writeNBytes(buf.getPos(),buf._getBuf());
    } else {

        // assign the message names for Upper Layer messages (typically requests)
        msgTypes["PLME-SET-TRX-STATE.request"] = SETTRXSTATE;
        msgTypes["PLME-GET.request"] = GET;
        msgTypes["PLME-SET.request"] = SET;
        msgTypes["PLME-CCA.request"] = CCA;
        msgTypes["PLME-ED.request"] = ED;
        msgTypes["PD-DATA.request"] = CONF;
        msgTypes["PLME-SET-PHY-PIB.request"] = SETREQUPPIB;

        switch(msgTypes[msg->getName()]) {
        case SETREQUPPIB:{
            SetPPIBRequest* req= check_and_cast<SetPPIBRequest *>(msg);
            b.writeByte(PLME_SET_PHY_PIB_REQUEST);
            b.writeByte(sizeof(PLME_SET_PHY_PIB_REQUEST)+sizeof(req->getPIBLQI())+sizeof(req->getPIBbandwidth())+sizeof(req->getPIBcca())+
                    sizeof(req->getPIBchansup())+sizeof(req->getPIBcurcha())+sizeof(req->getPIBcurpag())+sizeof(req->getPIBmaxframs())
                    +sizeof(req->getPIBrxgain())+sizeof(req->getPIBsamprate())+sizeof(req->getPIBshdr())+sizeof(req->getPIBsymOc())
                    +sizeof(req->getPIBtrPwr())+sizeof(req->getPIBtxgain())+sizeof(req->getPIBsignalstrengt()));
            b.writeByte((unsigned char)req->getPIBcca());
            b.writeUint32((unsigned int)req->getPIBchansup());
            b.writeByte((unsigned char)req->getPIBcurcha());
            b.writeByte((unsigned char)req->getPIBcurpag());
            b.writeByte((unsigned char)req->getPIBLQI());
            b.writeUint16((unsigned short) req->getPIBmaxframs());
            b.writeByte((unsigned char)req->getPIBshdr());
            b.writeByte((unsigned char)req->getPIBsymOc());
            b.writeByte((unsigned char)req->getPIBtrPwr());
            b.writeByte((unsigned char)req->getPIBrxgain());
            b.writeByte((unsigned char)req->getPIBtxgain());
            b.writeUint32((unsigned int)req->getPIBbandwidth());
            b.writeUint32((unsigned int)req->getPIBsamprate());
            b.writeByte((unsigned char) req->getPIBsignalstrengt());
            break;
        }
        case SETTRXSTATE: {
            b.writeByte(PLME_SET_TRX_STATE_REQUEST);
            b.writeByte(SIZEOF_PLME_SET_TRX_STATE_REQUEST);
            b.writeByte((phyState) msg->getKind());
            break;
        }
        case GET: {
            GetRequest* req;
            req = check_and_cast<GetRequest *>(msg);
            b.writeByte(PLME_GET_REQUEST);
            b.writeByte(SIZEOF_PLME_GET_REQUEST);
            b.writeByte((unsigned char) req->getPIBattr());
            break;
        }
        case SET: {
            SetRequest* req;
            req = check_and_cast<SetRequest *>(msg);
            b.writeByte(PLME_SET_REQUEST);

            if (req->getPIBattr() < 8) {
                if (req->getPIBattr() == 1) {
                    b.writeByte(SIZEOF_PLME_SET_REQUEST + sizeof(unsigned int));
                    b.writeByte((unsigned char) req->getPIBattr());
                    b.writeUint32((unsigned int) req->getValue());
                } else if (req->getPIBattr() == 6) {
                    b.writeByte(SIZEOF_PLME_SET_REQUEST + sizeof(unsigned short));
                    b.writeByte((unsigned char) req->getPIBattr());
                    b.writeUint16((unsigned short) req->getValue());
                } else {
                    b.writeByte(SIZEOF_PLME_SET_REQUEST + sizeof(unsigned char));
                    b.writeByte((unsigned char) req->getPIBattr());
                    b.writeByte((unsigned char) req->getValue());
                }
            }
            if (req->getPIBattr() < 12 && req->getPIBattr() >8 ) {
                if (req->getPIBattr() < 10){
                    b.writeByte(SIZEOF_PLME_SET_REQUEST + sizeof(unsigned char));
                    b.writeByte((unsigned char) req->getPIBattr());
                    b.writeByte((unsigned char) req->getValue());
                }else{
                    b.writeByte(SIZEOF_PLME_SET_REQUEST + sizeof(unsigned int));
                    b.writeByte((unsigned char) req->getPIBattr());
                    b.writeUint32((unsigned int) req->getValue());
                }

            }
            break;
        }
        case CCA: {
            b.writeByte(PLME_CCA_REQUEST);
            b.writeByte(SIZEOF_PLME_CCA_REQUEST);
            break;
        }
        case ED: {
            b.writeByte(PLME_ED_REQUEST);
            b.writeByte(SIZEOF_PLME_ED_REQUEST);
            break;
        }
        case CONF: {
            sEV << "IEEE802154Serializer: Serialization of confirmation messages is not supported!" << endl;
            break;
        }
        default: {
            throw cRuntimeError("IEEE802154Serializer: Unknown message type!");
        }
        }
    }
}

/*
 * deserializes a PHY Message SDU from Buffer b into a Message
 */
cMessage* IEEE802154Serializer::deserializeSDU(const Buffer &b)
{
    // reset buffer position for reading
    b.seek(0);

    // read message type and length
    uint8_t type = b.readByte();
    uint8_t lenghth= b.readByte(); // length is not needed

    switch(type) {
    case PD_DATA_CONFIRM: {
        cMessage* conf = new cMessage("PD-DATA.confirm");
        conf->setKind(b.readByte());
        return conf;
        break;
    }
    case PD_DATA_INDICATION: {
        pdDataInd *ind = new pdDataInd("PD-DATA.indication");
        ind->setPsduLength(b.readByte());
        ind->setPpduLinkQuality(b.readByte());
        ind->encapsulate(deserialize(b));
        return ind;
        break;
    }
    case PLME_CCA_CONFIRM: {
        cMessage *conf =  new cMessage("PLME-CCA.confirm");
        conf->setKind(b.readByte());
        return conf;
        break;
    }
    case PLME_ED_CONFIRM: {
        edConf *conf =  new edConf("PLME-ED.confirm");
        conf->setStatus(b.readByte());
        conf->setEnergyLevel(b.readByte());
        return conf;
        break;
    }
    case PLME_GET_CONFIRM: {
        GetConfirm *conf = new GetConfirm("PLME-GET.confirm");
        conf->setStatus(b.readByte());
        conf->setPIBattr(b.readByte());
        conf->setPIBind(1); //<-- todo
        switch (conf->getPIBattr()) {
        case channelSupported:
            conf->setValue(b.readUint32());
            break;
        case maxFrameDuration:
            conf->setValue(b.readUint16());
            break;
        default:
            conf->setValue(b.readByte());
        }
        return conf;
        break;
    }
    case PLME_SET_TRX_STATE_CONFIRM: {
        cMessage *conf = new cMessage("PLME-SET-TRX-STATE.confirm");
        conf->setKind(b.readByte());
        return conf;
        break;
    }
    case PLME_SET_CONFIRM: {
        SetConfirm *conf = new SetConfirm("PLME-SET.confirm");
        conf->setStatus(b.readByte());
        conf->setPIBattr(b.readByte());
        return conf;
        break;
    }
    case PLME_SET_PHY_PIB_CONFIRM:{
        SetPPIBConfirm *conf = new SetPPIBConfirm("PLME-SET-PHY-PIB.confirm");
        conf->setStatus(b.readByte());
        conf->setPIBcca(b.readByte());
        conf->setPIBchansup(b.readUint32());
        conf->setPIBcurcha(b.readByte());
        conf->setPIBcurpag(b.readByte());
        conf->setPIBLQI(b.readByte());
        conf->setPIBmaxframs(b.readUint16());
        conf->setPIBshdr(b.readByte());
        conf->setPIBsymOc(b.readByte());
        conf->setPIBtrPwr(b.readByte());
        conf->setPIBrxgain(b.readByte());
        conf->setPIBtxgain(b.readByte());
        conf->setPIBbandwidth(b.readUint32());
        conf->setPIBsamprate(b.readUint32());
        conf->setPIBsignalstrengt(b.readByte());
        return conf;
        break;
    }
    case PLME_SET_PHY_PIB_INDICATION:{
        SetPPIBIndication *conf = new SetPPIBIndication("PLME-SET-PHY-PIB.indication");
        conf->setStatus(b.readByte());
        conf->setPIBcca(b.readByte());
        conf->setPIBchansup(b.readUint32());
        conf->setPIBcurcha(b.readByte());
        conf->setPIBcurpag(b.readByte());
        conf->setPIBLQI(b.readByte());
        conf->setPIBmaxframs(b.readUint16());
        conf->setPIBshdr(b.readByte());
        conf->setPIBsymOc(b.readByte());
        conf->setPIBtrPwr(b.readByte());
        conf->setPIBrxgain(b.readByte());
        conf->setPIBtxgain(b.readByte());
        conf->setPIBbandwidth(b.readUint32());
        conf->setPIBsamprate(b.readUint32());
        conf->setPIBsignalstrengt(b.readByte());
        return conf;
        break;
    }
    default: {
        throw cRuntimeError("IEEE802154Serializer: Cannot deserialize message type %u!", type);
    }
    }

    return nullptr;
}

/*
 * cPacket pkt will be written into Buffer &b, ...
 */
void IEEE802154Serializer::serialize(const cPacket *pkt, Buffer &b)
{
    sEV << "Serialize packet " << pkt->getName() << " (Time: " << pkt->getArrivalTime() << ")" << endl;

    const mpdu *pdu = nullptr;

    // ---------------- MHR ----------------
    if (dynamic_cast<const mpdu *>(pkt))
    {
        pdu = static_cast<const mpdu *>(pkt);

        uint16_t fcf = pdu->getFcf();
        uint8_t frameType = (fcf >> ftShift) & 7;
        bool secuEnabled = (fcf >> secuShift) & 1;  //secShift
        uint8_t d_addr_mode = (fcf >> damShift) & 3;
        uint8_t s_addr_mode = (fcf >> samShift) & 3;

        b.writeUint16(fcf);
        b.writeByte(pdu->getSqnr());

        if (d_addr_mode == addrShort)
        {
            b.writeUint16(pdu->getDestPANid());
            b.writeUint16(pdu->getDest().getShortAddr());
        } else if (d_addr_mode == addrLong)
        {
            b.writeUint16(pdu->getDestPANid());
            b.writeUint64(pdu->getDest().getInt());
        }
        if (s_addr_mode == addrShort)
        {
            b.writeUint16(pdu->getSrcPANid());
            b.writeUint16(pdu->getSrc().getShortAddr());
        } else if (s_addr_mode == addrLong)
        {
            b.writeUint16(pdu->getSrcPANid());
            b.writeUint64(pdu->getSrc().getInt());
        }

        //std::cout << "Serializer Stream after fcf: " << b.getByteStream(b.getPos()) << "\n";

        if (secuEnabled)
        {
            uint8_t secu = 0;
            secu |= pdu->getAsh().secu.Seculevel & 7;
            secu |= (pdu->getAsh().secu.KeyIdMode & 3) << 3;
            b.writeByte(secu);
            b.writeUint32((uint32_t) pdu->getAsh().FrameCount);
            if (pdu->getAsh().secu.KeyIdMode)
            {
                switch(pdu->getAsh().secu.KeyIdMode & 3)
                {
                    case 0x00:
                        // Nothing to do here
                        break;
                    case 0x01:
                        b.writeByte(pdu->getAsh().KeyIdentifier.KeyIndex);
                        break;
                    case 0x02:
                    {
                        b.writeUint32(pdu->getAsh().KeyIdentifier.KeySource);
                        b.writeByte(pdu->getAsh().KeyIdentifier.KeyIndex);
                        break;
                    }
                    case 0x03:
                    {
                        b.writeUint64(pdu->getAsh().KeyIdentifier.KeySource);
                        b.writeByte(pdu->getAsh().KeyIdentifier.KeyIndex);
                        break;
                    }
                    default:
                        //throw cRuntimeError("IEEE802154Serializer: Unknown key id mode %i!", pdu->getAsh().secu.KeyIdMode);
                        sEV << "IEE802154Serializer: Unknown key id mode " << pdu->getAsh().secu.KeyIdMode << "!" << endl;
                    }
            }
        }

        // ------------ MAC Payload ------------
        switch(frameType)
        {
            // BEACON
            case Beacon:
            {
                if (check_and_cast<const beaconFrame *>(pkt))
                {
                    const beaconFrame *beacon = static_cast<const beaconFrame *>(pkt);

                    uint16_t sfs = 0;
                    sfs |= beacon->getSfSpec().BO & 15;
                    sfs |= (beacon->getSfSpec().SO & 15) << 4;
                    sfs |= (beacon->getSfSpec().finalCap & 15) << 8;
                    sfs |= beacon->getSfSpec().battLifeExt << 12;
                    sfs |= beacon->getSfSpec().panCoor << 14;
                    sfs |= beacon->getSfSpec().assoPmt << 15;
                    b.writeUint16(sfs);

                    uint8_t gtss = 0;
                    gtss |= beacon->getGtsFields().gtsSpec.count & 7;
                    gtss |= beacon->getGtsFields().gtsSpec.permit << 7;
                    b.writeByte(gtss);

                    uint8_t dirs = 0;
                    dirs |= (beacon->getGtsFields().gtsDirs.mask & 127);
                    b.writeByte(dirs);

                    for (uint8_t i=0; i<beacon->getGtsListArraySize(); i++) // TODO: check iterator
                    {
                        b.writeUint16(beacon->getGtsList(i).devShortAddr);
                        uint8_t gtsd = 0;
                        gtsd |= beacon->getGtsList(i).startSlot & 15;
                        gtsd |= (beacon->getGtsList(i).length & 15) << 4;
                        b.writeByte(gtsd);
                    }

                    uint8_t pafs = 0;
                    pafs |= (beacon->getPaFields().numShortAddr & 7);
                    pafs |= (beacon->getPaFields().numExtendedAddr & 7) << 4;
                    b.writeByte(pafs);

                    uint8_t addr_count = 0;
                    for (int i=0; i<beacon->getPaFields().numShortAddr; i++)
                    {
                        b.writeUint16(beacon->getPaFields().addrList[addr_count].getShortAddr());
                        addr_count++;
                    }
                    for (int i=0; i<beacon->getPaFields().numExtendedAddr; i++)
                    {
                        b.writeUint64(beacon->getPaFields().addrList[addr_count].getInt());
                        addr_count++;
                    }

                    //std::cout << "Serializer Stream after Beacon: " << b.getByteStream(b.getPos()) << "\n";

                    if (dynamic_cast<const RawPacket*>(pdu->getEncapsulatedPacket()))
                    {
                        const RawPacket *payload = static_cast<const RawPacket*>(pdu->getEncapsulatedPacket());
                        for (int i=0; i<payload->getByteLength(); i++) {
                            b.writeByte(payload->getByteArray().getData(i));
                        }
                    }

                    //std::cout << "Serializer Stream after Beacon Payload: " << b.getByteStream(b.getPos()) << "\n";

                }
                else
                    throw cRuntimeError("IEEE802154Serializer: Cannot serialize beacon frame!");

                break;
            }

            case Data:
            {
                if (dynamic_cast<const RawPacket*>(pdu->getEncapsulatedPacket()))
                {
                    const RawPacket *payload = static_cast<const RawPacket*>(pdu->getEncapsulatedPacket());
                    for (int i=0; i<payload->getByteLength(); i++) {
                        b.writeByte(payload->getByteArray().getData(i));
                    }
                }
                break;
            }

            case Ack:
            {
                // Nothing to do here!
                break;
            }

            case Command:
            {
                if (dynamic_cast<const CmdFrame *>(pkt))
                {
                    const CmdFrame *cmdFrame = static_cast<const CmdFrame *>(pkt);
                    b.writeByte(cmdFrame->getCmdType());

                    if (dynamic_cast<const AssoCmdreq *>(pkt))
                    {
                        const AssoCmdreq *assoReq = static_cast<const AssoCmdreq *>(pkt);
                        uint8_t cif = 0;
                        cif |= assoReq->getCapabilityInformation().alterPANCoor & 1;
                        cif |= (assoReq->getCapabilityInformation().FFD & 1) << 1;
                        //cif |= (assoReq->getCapabilityInformation().powSrc & 1) << 2; // ERROR invalid operands of types 'const char* const' and 'int' to binary operator&
                        cif |= (assoReq->getCapabilityInformation().recvOnWhenIdle & 1) << 3;
                        cif |= (assoReq->getCapabilityInformation().secuCapable & 1) << 6;
                        cif |= (assoReq->getCapabilityInformation().alloShortAddr & 1) << 7;
                        b.writeByte(cif);
                    }
                    else if (dynamic_cast<const AssoCmdresp *>(pkt))
                    {
                        const AssoCmdresp *assoResp = static_cast<const AssoCmdresp *>(pkt);
                        b.writeUint16(assoResp->getShortAddress());
                        b.writeByte(assoResp->getStatus());
                    }
                    else if (dynamic_cast<const DisAssoCmd *>(pkt))
                    {
                        const DisAssoCmd *disAsso = static_cast<const DisAssoCmd *>(pkt);
                        b.writeByte(disAsso->getDisassociateReason());
                    }
                    // Noting to do for DataRequest / PAN ID conflict notification / Orphan notification / Beacon request
                    else if (dynamic_cast<const RealignCmd *>(pkt))
                    {
                        const RealignCmd *realign = static_cast<const RealignCmd *>(pkt);
                        b.writeUint16(realign->getPANId());
                        b.writeUint16(realign->getCoordShortAddr());
                        b.writeByte(realign->getLogicalChannel());
                        b.writeUint16(realign->getShortAddr());
                        if (realign->getChannelPage()) b.writeByte(realign->getChannelPage());
                    }
                    else if (dynamic_cast<const GTSCmd *>(pkt))
                    {
                        const GTSCmd *gts = static_cast<const GTSCmd *>(pkt);
                        uint8_t gtsc = 0;
                        gtsc |= gts->getGTSCharacteristics().length & 15;
                        gtsc |= (gts->getGTSCharacteristics().isRecvGTS & 1) << 4;
                        gtsc |= (gts->getGTSCharacteristics().Type & 1) << 5;
                        b.writeByte(gtsc);
                    }
                    else
                        break;
                }
                else
                    throw cRuntimeError("IEEE802154Serializer: Cannot serialize command frame!");

                break;
            }

            default:
            {
                throw cRuntimeError("IEEE802154Serializer: Unknown frame type of mpdu!");
            }
        }

        // ---------------- MFR ----------------
        b.writeUint16(pdu->getFcs());

        //std::cout << "Serializer Stream: " << b.getByteStream(b.getPos()) << "\n";
    }
    else
        throw cRuntimeError("IEEE802154Serializer: Frame is not a mpdu!");
}

/*
 * deserialize a Packet from "wire" into Buffer b
 */
cPacket* IEEE802154Serializer::deserialize(const Buffer &b)
{
    cPacket *frame = new cPacket();
    mpdu *pdu = new mpdu();

    std::cout << "(Serializer):Buffer_Pos: " << b.getRemainingSize() << std::endl;

    // reset buffer position for reading
    //b.seek(0);

    // set Byte length of Frame, OMNeT++ specific for casting packet
    pdu->setByteLength(b.getRemainingSize());
    uint16_t fcf = b.readUint16();
    uint8_t type = (fcf >> 0) & 7;
    bool secuEnabled = (fcf >> 3) & 1;
    uint8_t d_addr_mode = (fcf >> 10) & 3;
    uint8_t frame_ver = (fcf >> 12) & 3;
    uint8_t s_addr_mode = (fcf >> 14) & 3;

    pdu->setFcf(fcf);
    pdu->setSqnr(b.readByte());

    if (!(d_addr_mode == noAddr || d_addr_mode == 0x01))
    {
        pdu->setDestPANid(ntohs(b.readUint16()));

        if (d_addr_mode == addrShort)
        {
            MACAddressExt *dest = new MACAddressExt();
            dest->setShortAddr(ntohs(b.readUint16()));
            pdu->setDest(*dest);

        }
        else if (d_addr_mode == addrLong)
        {
            MACAddressExt *dest = new MACAddressExt(b.readUint64());
            pdu->setDest(*dest);
        }
    }

    if (!(s_addr_mode == noAddr || s_addr_mode == 0x01))
    {
        pdu->setSrcPANid(ntohs(b.readUint16()));

        if (s_addr_mode == addrShort)
        {
            MACAddressExt *src = new MACAddressExt();
            src->setShortAddr(ntohs(b.readUint16()));
            pdu->setSrc(*src);
        }
        else if (s_addr_mode == addrLong)
        {
            MACAddressExt *src = new MACAddressExt(b.readUint64());
            pdu->setSrc(*src);
        }
    }

    if (secuEnabled)
    {
        struct Ash securityHdr { };
        uint8_t secuCtrl = b.readByte();
        securityHdr.secu.Seculevel = (secuCtrl & 7);
        securityHdr.secu.KeyIdMode = (secuCtrl & 24) >> 4;
        securityHdr.FrameCount = ntohl(b.readUint32());

        if (securityHdr.secu.KeyIdMode == 0x01)
        {
            securityHdr.KeyIdentifier.KeyIndex = b.readByte();
        }
        else if (securityHdr.secu.KeyIdMode == 0x02)
        {
            securityHdr.KeyIdentifier.KeySource = ntohl(b.readUint32());
            securityHdr.KeyIdentifier.KeyIndex = b.readByte();
        }
        else if (securityHdr.secu.KeyIdMode == 0x03)
        {
            securityHdr.KeyIdentifier.KeySource = b.readUint64();
            securityHdr.KeyIdentifier.KeyIndex = b.readByte();
        }

        pdu->setAsh(securityHdr);
    }

    switch(type)
    {
        case Beacon:
        {
            beaconFrame *beacon = new beaconFrame();
            beacon->setName("Beacon");

            struct SuperframeSpec superframe { };
            uint16_t sfs = ntohs(b.readUint16());
            superframe.BO = (sfs & 15);
            superframe.SO = (sfs & 240) >> 4;
            superframe.finalCap = (sfs & 3840) >> 8;
            superframe.battLifeExt = (sfs & 4096) >> 12;
            superframe.panCoor = (sfs & 16384) >> 14;
            superframe.assoPmt = (sfs & 32768) >> 15;
            beacon->setSfSpec(superframe);

            struct GTSFields gtsFields { };

            uint8_t gtsSpec = b.readByte();
            gtsFields.gtsSpec.count = (gtsSpec & 7);
            gtsFields.gtsSpec.permit = (gtsSpec & 128) >> 7;

            if (gtsFields.gtsSpec.count)
            {
                uint8_t mask = b.readByte();
                gtsFields.gtsDirs.mask = mask & 127;

                //struct GTSDescriptor gtsDesc { };

                for (uint8_t i=0; i<gtsFields.gtsSpec.count; i++)
                {
                    // TODO: GTS deserialization
                    //gtsFields.gtsList[i].devShortAddr = ntohs(b.readUint16());
                    //uint8_t gtsDesc = b.readByte();
                    //gtsFields.gtsList[i].startSlot = gtsDesc & 15;
                    //gtsFields.gtsList[i].length = (gtsDesc & 240) >> 4;
                }
            }

            beacon->setGtsFields(gtsFields);

            struct PendingAddrFields paif { };
            uint8_t pasf = b.readByte();
            uint8_t addr_count = 0;
            paif.numShortAddr = (pasf & 7);
            paif.numExtendedAddr = (pasf & 112) >> 4;

            for (uint8_t i=0; i<paif.numShortAddr; i++)
            {
                MACAddressExt *shortAddr = new MACAddressExt();
                shortAddr->setShortAddr(ntohs(b.readUint16()));
                paif.addrList[addr_count] = *shortAddr;
                addr_count++;
            }

            for (uint8_t i=0; i<paif.numExtendedAddr; i++)
            {
                MACAddressExt *extendedAddr = new MACAddressExt(b.readUint64());
                paif.addrList[addr_count] = *extendedAddr;
                addr_count++;
            }

            beacon->setPaFields(paif);

            // beacon payload
            // TODO: payload length without FCS -> write payload to packet
            RawPacket *payload = new RawPacket();
            ByteArray bytes = ByteArray();
            int payloadLen = b.getRemainingSize(sizeof(beacon->getFcs()));

            unsigned char *ptr = new unsigned char[payloadLen]();
            for (int i=0; i<payloadLen; i++) {
                ptr[i] = b.readByte();
            }

            bytes.setDataFromBuffer(ptr, payloadLen);
            delete[] ptr;

            payload->setByteLength(payloadLen);
            payload->setByteArray(bytes);

            pdu->encapsulate(dynamic_cast<cPacket*>(payload));

            break;
        }
        case Data:
        {
            /* TODO: payload length without FCS -> write payload to packet, calc FCS for payload
             * see IEEE Standard ref: -2006 @Chapter: 7.2.1.9 FCS field
             *
             * "The FCS field is 2 octets in length and contains a 16-bit ITU-T CRC. The FCS is calculated over the MHR
             *   and MAC payload parts of the frame."
             */
            RawPacket *payload = new RawPacket();
            ByteArray bytes = ByteArray();
            //int payloadLen = b.getRemainingSize(sizeof(pdu->getFcs()));
            int payloadLen = b.getRemainingSize();                 // ignore FCS, if present
            unsigned char *ptr = new unsigned char[payloadLen]();
            for (int i=0; i<payloadLen; i++) {
                ptr[i] = b.readByte();
            }

            bytes.setDataFromBuffer(ptr, payloadLen);
            delete[] ptr;

            payload->setByteLength(payloadLen);
            payload->setByteArray(bytes);

            pdu->setName("Data");
            pdu->encapsulate(dynamic_cast<cPacket*>(payload));
            pdu->setByteLength(pdu->getByteLength()-payloadLen);

            break;
        }
        case Ack:
        {
            // There is no payload in case of Ack
            pdu->setName("Ack");
            break;
        }
        case Command:
        {
            CmdFrame *cmd = new CmdFrame();

            uint8_t cmdType = b.readByte();
            cmd->setCmdType(cmdType);

            switch(cmdType)
            {
                case Ieee802154_ASSOCIATION_REQUEST:
                {
                    AssoCmdreq *assoReq = new AssoCmdreq();
                    assoReq->setName("AssociationRequest");
                    assoReq->setCmdType(cmdType);
                    /*
                    struct DevCapability devCap { };
                    uint8_t devCap_temp = b.readByte();
                    devCap.alterPANCoor = (devCap_temp & 1);
                    devCap.FFD = (devCap_temp & 2) >> 1;
                    //devCap.powSrc = (devCap_temp & 4) >> 2;   // Error invalid conversion from int to const char*
                    devCap.recvOnWhenIdle = (devCap_temp & 8) >> 3;
                    devCap.secuCapable = (devCap_temp & 64) >> 6;
                    devCap.alloShortAddr = (devCap_temp & 128) >> 7;
                    assoReq->setCapabilityInformation(devCap);
                    */
                    cmd = assoReq;
                    break;
                }
                case Ieee802154_ASSOCIATION_RESPONSE:
                {
                    AssoCmdresp *assoResp = new AssoCmdresp();
                    assoResp->setName("AssociationResponse");
                    assoResp->setCmdType(cmdType);
                    assoResp->setShortAddress(ntohs(b.readUint16()));
                    assoResp->setStatus(b.readByte());
                    cmd = assoResp;
                    break;
                }
                case Ieee802154_DISASSOCIATION_NOTIFICATION:
                {
                    DisAssoCmd *disAsso = new DisAssoCmd();
                    disAsso->setName("DisassociationNotification");
                    disAsso->setCmdType(cmdType);
                    disAsso->setDisassociateReason(b.readByte());
                    cmd = disAsso;
                    break;
                }
                case Ieee802154_DATA_REQUEST:
                {
                    // No payload
                    cmd->setName("DataRequest");
                    break;
                }
                case Ieee802154_PANID_CONFLICT_NOTIFICATION:
                {
                    // No payload
                    cmd->setName("PANIDConflictNotification");
                    break;
                }
                case Ieee802154_ORPHAN_NOTIFICATION:
                {
                    // No payload
                    cmd->setName("OrphanNotification");
                    break;
                }
                case Ieee802154_BEACON_REQUEST:
                {
                    // No payload
                    cmd->setName("BeaconRequest");
                    break;
                }
                case Ieee802154_COORDINATOR_REALIGNMENT:
                {
                    RealignCmd *realign = new RealignCmd();
                    realign->setName("CoordinatorRealignment");
                    realign->setCmdType(cmdType);
                    realign->setPANId(ntohs(b.readUint16()));
                    realign->setCoordShortAddr(ntohs(b.readUint16()));
                    realign->setLogicalChannel(b.readByte());
                    realign->setShortAddr(ntohs(b.readUint16()));
                    if (frame_ver == 0x01) realign->setChannelPage(b.readByte());
                    cmd = realign;
                    break;
                }
                case Ieee802154_GTS_REQUEST:
                {
                    GTSCmd *gts = new GTSCmd();
                    cmd->setName("GTSRequest");
                    struct GTSDescriptor gtsDesc { };
                    uint8_t gts_temp = b.readByte();
                    gtsDesc.length = (gts_temp & 15);
                    gtsDesc.isRecvGTS = (gts_temp & 16) >> 4;
                    gtsDesc.Type = (gts_temp & 32) >> 5;
                    gts->setGTSCharacteristics(gtsDesc);
                    cmd = gts;
                    break;
                }
                case Ieee802154_POLL_REQUEST:
                {
                    // No payload
                    cmd->setName("PollRequest");
                    break;
                }

                default:
                {
                    EV_ERROR << "IEEE802154Serializer: Cannot deserialize command frame: Type " << cmdType << " not supported.";
                    b.setError();
                    return nullptr;
                }
            }

            cmd->addByteLength(pdu->getByteLength());
            cmd->setFcf(pdu->getFcf());
            cmd->setSqnr(pdu->getSqnr());
            cmd->setAsh(pdu->getAsh());
            cmd->setDestPANid(pdu->getDestPANid());
            cmd->setDest(pdu->getDest());
            cmd->setSrcPANid(pdu->getSrcPANid());
            cmd->setSrc(pdu->getSrc());
            cmd->setArrival(pdu->getArrivalModule(), pdu->getArrivalGateId());
            cmd->setArrivalTime(pdu->getArrivalTime());
            cmd->setTimestamp(pdu->getTimestamp());

            pdu = cmd;

            break;
        }

        default:
        {
            EV_ERROR << "IEEE802154Serializer: Cannot deserialize packet: Type " << type << " not supported.";
            b.setError();
            return nullptr;
        }
    }

    frame = pdu;

    sEV << "Deserialized: " << frame << " (Time: " << frame->getArrivalTime() << ")" << endl;

    return frame;
}
