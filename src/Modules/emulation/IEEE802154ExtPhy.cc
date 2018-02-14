//
// Copyright (C) 2013 Matti Schnurbusch (original code, IEEE802154Phy)
// Copyright (C) 2015 Michael Kirsche   (clean-up, ported for INET 2.x)
// Copyright (C) 2018 Sebastian Boehm   (adaption for use as external transceiver)
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

#include "IEEE802154ExtPhy.h"

Define_Module(IEEE802154ExtPhy);

void IEEE802154ExtPhy::initialize(int stage)
{
    cSimpleModule::initialize(stage);
    if (stage == 0)
    {
        // initialize the debug output bool from NED parameter value
        phyDebug = (hasPar("phyDebug") ? (par("phyDebug").boolValue()) : (false));

        // assign the message names for Upper Layer messages (typically requests)
        mappedUpperLayerMsgTypes["PLME-SET-TRX-STATE.request"] = SETTRXSTATE;
        mappedUpperLayerMsgTypes["PLME-GET.request"] = GET;
        mappedUpperLayerMsgTypes["PLME-SET.request"] = SET;
        mappedUpperLayerMsgTypes["PLME-CCA.request"] = CCA;
        mappedUpperLayerMsgTypes["PLME-ED.request"] = ED;
        mappedUpperLayerMsgTypes["PD-DATA.request"] = CONF;

        // assign the message names for Lower Layer messages (typically confirms)
        mappedLowerLayerMsgTypes["PLME-SET-TRX-STATE.confirm"] = SETTRXSTATE;
        mappedLowerLayerMsgTypes["PLME-GET.confirm"] = GET;
        mappedLowerLayerMsgTypes["PLME-SET.confirm"] = SET;
        mappedLowerLayerMsgTypes["PLME-CCA.confirm"] = CCA;
        mappedLowerLayerMsgTypes["PLME-ED.confirm"] = ED;
        mappedLowerLayerMsgTypes["PD-DATA.confirm"] = CONF;

        //  search for modules
        cModule *host = getParentModule()->getParentModule();
        cModule *network = getParentModule()->getParentModule()->getParentModule();

        for (cModule::SubmoduleIterator i(network); !i.end(); i++) {
            cModule *submodp = i();
            // todo: by name?
            if (std::string(submodp->getFullName()) == "IEEE802154ExtInterface") {
                extInterfaceID = submodp->getId();
            }
        }

        this->moduleID = host->getId();
    }

}

ppdu *IEEE802154ExtPhy::generatePPDU(cMessage *psdu, bool ackFlag)
{
    ppdu *pdu = new ppdu("PD-DATA");
    cPacket *pk = dynamic_cast<cPacket *>(psdu);
    pdu->setSFD(229); // set SFD to 11100101 except for TODO ASK

    if (ackFlag)
    {
        pdu->setPHR(5);
    }
    else
    {
        pdu->setPHR(pk->getByteLength() + 6);
        pdu->setByteLength(pk->getByteLength() + 6); // needed for calculation in Radio Module
    }

    phyEV << "The Frame length (PHR in PHY) is set to " << (unsigned short) pdu->getPHR() << endl;
    pdu->encapsulate(pk);
    return pdu;
}

void IEEE802154ExtPhy::handleMessage(cMessage *msg)
{
    phyEV << "Got Message " << msg->getName() << endl;

    if (msg->arrivedOn("PLME_SAP")) // --> Message arrived from MAC over PHY-Management-Layer-Entity SAP
    {
        if (dynamic_cast<AssoCmdreq *>(msg) != NULL)
        {
            sendDirect(msg, simulation.getModule(extInterfaceID), "inDirect"); // to extInterface
            return;
        }
        else if (dynamic_cast<DisAssoCmd*>(msg) != NULL)
        {
            sendDirect(msg, simulation.getModule(extInterfaceID), "inDirect"); // to extInterface
            return;
        }
        else if (dynamic_cast<GTSCmd*>(msg) != NULL)
        {
            sendDirect(msg, simulation.getModule(extInterfaceID), "inDirect"); // to extInterface
            return;
        }
        else if (dynamic_cast<CmdFrame*>(msg) != NULL)
        {
            sendDirect(msg, simulation.getModule(extInterfaceID), "inDirect"); // to extInterface
            return;
        }

        switch (mappedUpperLayerMsgTypes[msg->getName()]) // --> PHY-Management Request Service Primitives
        {
            case SETTRXSTATE: {
                phyEV << "PLME-SETTRXSTATE.request arrived -> instruct external PHY to set the TRX state \n";
                sendDirect(msg, simulation.getModule(extInterfaceID), "inDirect"); // to extInterface
                break;
            }

            case GET: {
                phyEV << "PLME-GET.request arrived -> instruct external PHY to get the PhyPIB attribute \n";
                GetRequest* PhyPIBGet;
                PhyPIBGet = check_and_cast<GetRequest *>(msg);
                sendDirect(PhyPIBGet, simulation.getModule(extInterfaceID), "inDirect"); // to extInterface
                break;
            }

            case SET: {
                phyEV << "PLME-SET.request arrived -> instruct external PHY to set the PhyPIB attribute \n";
                SetRequest* PhyPIBSet;
                PhyPIBSet = check_and_cast<SetRequest *>(msg);
                sendDirect(PhyPIBSet, simulation.getModule(extInterfaceID), "inDirect"); // to extInterface
                break;
            }

            case CCA: {
                phyEV << "PLME-CCA.request arrived -> instruct external PHY to perform a CCA \n";
                sendDirect(msg, simulation.getModule(extInterfaceID), "inDirect"); // to extInterface
                break;
            }

            case ED: {
                phyEV << "PLME-ED.request arrived -> instruct external PHY to perform an ED \n";
                sendDirect(msg, simulation.getModule(extInterfaceID), "inDirect"); // to extInterface
                break;
            }

            default: {
                error("Message %s with kind: %d arrived on PLME-SAP is not defined! \n", msg->getKind(), msg->getName());
                break;
            }
        } // switch (mappedMsgTypes[msg->getName()])
    } // if (msg->arrivedOn("PLME_SAP"))
    else if (msg->arrivedOn("PD_SAP")) // --> Message arrived from MAC layer over PHY-DATA SAP
    {
        ppdu *pdu = generatePPDU(msg, true);
        sendDirect(pdu, simulation.getModule(extInterfaceID), "inDirect"); // to extInterface
        return;
    }
    else if (msg->arrivedOn("inFromExt")) // --> Message arrived from external interface
    {
        if (dynamic_cast<AckFrame *>(msg) != NULL)
        {
            send(msg, "outPD");
            return;
        }
        else if (dynamic_cast<AssoCmdreq *>(msg) != NULL)
        {
            send(msg, "outPD");
            return;
        }
        else if (dynamic_cast<AssoCmdresp *>(msg) != NULL)
        {
            send(msg, "outPD");
            return;
        }
        else if (dynamic_cast<DisAssoCmd*>(msg) != NULL)
        {
            send(msg, "outPD");
            return;
        }
        else if (dynamic_cast<GTSCmd*>(msg) != NULL)
        {
            send(msg, "outPD");
            return;
        }
        else if (dynamic_cast<CmdFrame*>(msg) != NULL)
        {
            error("just for testing remove later, this should be a beacon request, name is %s \n", msg->getName()); // XXX remove after testing
            send(msg, "outPD");
            return;
        }
        else if (dynamic_cast<pdDataInd *>(msg) != NULL)
        {
            pdDataInd *pdu = check_and_cast<pdDataInd*>(msg);
            cPacket* payload = pdu->decapsulate();  // use cPacket since it can either be an MPDU or an ACK
            //payload->setKind(pdu->getPpduLinkQuality());  // FIXME we cannot hide LQI in kind because PhyIndication enums are saved there for MAC filtering
            // XXX PHY should actually forward the pdDataIndication to the MAC, not decapsulate and only forward the PPDU
            // LQI from pdDataIndication is needed for mscp.DataIndication
            // in function: void IEEE802154Mac::sendMCPSDataIndication(mpdu* rxData)
            phyEV << "is sending up the Payload of " << pdu->getName() << " which is a " << payload->getName() << endl;

            send(payload, "outPD");
            delete (pdu);
            return;
        }

        switch (mappedLowerLayerMsgTypes[msg->getName()]) // --> PHY-Management Confirm Service Primitives
        {
            case CONF: {
                send(msg, "outPD");
                return;
            }

            case CCA: {
                msg->setKind(phy_IDLE); // <-- temp ignore phy state from chip module
                send(msg, "outPLME");
                return;
            }
            case SETTRXSTATE:
            case GET:
            case SET:
            case ED: {
                msg->setKind(phy_SUCCESS); // <-- temp ignore phy state from chip module
                send(msg, "outPLME");
                return;
            }

            default: {
                error("Message %s with kind: %d arrived from external interface is undetermined! \n", msg->getKind(), msg->getName());
                break;
            }
        }
    } // if (msg->arrivedOn("inFromExt"))
}
