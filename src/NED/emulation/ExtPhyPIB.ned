//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 
package ieee802154.src.NED.emulation;

simple ExtPhyPIB
{
    parameters:
        int phyCurrentChannel = default(0);         // initial channel to be used
      //  int phyChannelsSupported= default(0);   // possible channels to be used
        int phyTransmitPower= default(0);          // transmission power to be used
        int phyCCAMode= default(0);                // 3 possible CCA Modes as described in the 2006 revision of the standard
        int phyCurrentPage= default(0);            // initial page to be used
        int phySHRDuration= default(0);            // Duration of the sync header
        double phySymbolsPerOctet= default(0.0);        // Number of symbols to identify 1 octet of data
        int phyMaxFrameDuration= default(0);
        int phyTRXstatus= default(0);
        int phyLQI= default(0);
        int phytxgain= default(0);
        int phyrxgain= default(0);
        int phybandwidth= default(0);
        int physampling_rate= default(0);
        
        @display("i=block/mac");
    gates:
//        input SAP_in;
//        output SAP_out;
        
        input inDirect @directIn;
}