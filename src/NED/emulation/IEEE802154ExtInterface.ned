package ieee802154.src.NED.emulation;

//
// This file is part of an OMNeT++/OMNEST simulation example.
//
// Copyright (C) 1992-2015 Andras Varga
//                    2017 Christoph Schwalbe
//
// This file is distributed WITHOUT ANY WARRANTY. See the file
// `license' for details on this and other legal matters.
//

//
// A real-time interface
//
simple IEEE802154ExtInterface
{
    parameters:
        @signal[arrival](type="long");
        @statistic[numRecvBytes](title="Bytes"; source="arrival"; record=vector,stats; interpolationmode=none);
        @display("i=device/lan-bus_l");
    gates:
        inout g;
        input inDirect @directIn @labels(IEEE802154ExtInterface);
}