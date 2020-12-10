/*
 * Copyright (c) Fabio Falcinelli 2016.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.github.ffalcinelli.jdivert.windivert;

import com.github.ffalcinelli.jdivert.Enums;
import com.github.ffalcinelli.jdivert.Enums.Layer;
import com.sun.jna.Structure;
import com.sun.jna.Union;
import com.sun.jna.platform.win32.WinDef;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Represents the "address" of a captured or injected packet. The address includes the packet's headers interfaces and the packet direction.
 * For more information check <a href="https://reqrypt.org/windivert-doc.html#divert_address">https://reqrypt.org/windivert-doc.html#divert_address</a>
 */
public class WinDivertAddress extends Structure {
	
	private static final int LAYER_OFFSET = 0;
	private static final int EVENT_OFFSET = 8;
	private static final int SNIFFED_OFFSET = 16;
	private static final int OUTBOUND_OFFSET = 17;
	private static final int LOOPBACK_OFFSET = 18;
	private static final int IMPOSTER_OFFSET = 19;
	private static final int IPV6_OFFSET = 20;
	private static final int IPCHECKSUM_OFFSET = 21;
	private static final int TCPCHECKSUM_OFFSET = 22;
	private static final int UDPCHECKSUM_OFFSET = 23;
	
	
	public WinDef.LONGLONG timestamp;
	public WinDef.UINT data1;
	public WinDef.UINT reserved2;
	
	public static class UNION extends Union {
		public WinDivertDataNetwork Network;
		public WinDivertDataFlow Flow;
		public WinDivertDataSocket Socket;
		public WinDivertDataReflect Reflect;
		
		@Override
		public boolean equals(Object o) {
			if(o == null) return false;
			if(!(o instanceof UNION)) return false;
			UNION u = (UNION) o;
			
			if(Network == null) {
				if(u.Network != null) return false;
			}else if(u.Network == null) {
				return false;
			}else {
				return Network.equals(u.Network);
			}
			
			if(Flow == null) {
				if(u.Flow != null) return false;
			}else if(u.Flow == null) {
				return false;
			}else {
				return Flow.equals(u.Flow);
			}
			
			if(Socket == null) {
				if(u.Socket != null) return false;
			}else if(u.Socket == null) {
				return false;
			}else {
				return Socket.equals(u.Socket);
			}
			
			if(Reflect == null) {
				if(u.Reflect != null) return false;
			}else if(u.Reflect == null) {
				return false;
			}else {
				return Reflect.equals(u.Reflect);
			}
			
			return true;
		}
		
		@Override
		public int hashCode() {
			return Objects.hash(Network, Flow, Socket, Reflect);
		}
	}
	
	public UNION LayerUnion;
	
	
	/*@Override
	public void write() {
		super.write();
		LayerUnion.write();
	}*/
	
	@Override
	public void read() {
		super.read();
		
		switch(getLayerType()) {
		case NETWORK:
		case NETWORK_FORWARD:
			LayerUnion.setType(WinDivertDataNetwork.class);
			break;
		case FLOW:
			LayerUnion.setType(WinDivertDataFlow.class);
			break;
		case SOCKET:
			LayerUnion.setType(WinDivertDataSocket.class);
			break;
		case REFLECT:
			LayerUnion.setType(WinDivertDataReflect.class);
			break;
		default:
			throw new IllegalArgumentException("Can't handle layer of type: "+getLayerType());
		}
		
		LayerUnion.read();
	}
	
	public static WinDivertAddress createInboundNetworkWinDivertAddress(int networkInterface, int subInterface, boolean imposter, 
			boolean validIpChecksum, boolean validTcpChecksum, boolean validUdpChecksum) {
		
		WinDivertAddress addr = new WinDivertAddress();
		addr.setIsOutbound(false);
		
		addr.setLayerType(Layer.NETWORK);
		addr.LayerUnion = new UNION();
		
		addr.LayerUnion.Network = new WinDivertDataNetwork();
		addr.LayerUnion.Network.IfIdx = new WinDef.UINT(networkInterface);
		addr.LayerUnion.Network.SubIfIdx = new WinDef.UINT(subInterface);
		
		addr.setIsImposter(imposter);
		
		addr.setIsIPChecksum(validIpChecksum);
		addr.setIsTCPChecksum(validTcpChecksum);
		addr.setIsUDPChecksum(validUdpChecksum);
		
		return addr;
	}
	
	public static WinDivertAddress createOutboundNetworkWinDivertAddress(boolean imposter, boolean validIpChecksum, boolean validTcpChecksum, boolean validUdpChecksum) {
		
		WinDivertAddress addr = new WinDivertAddress();
		addr.setIsOutbound(true);
		
		addr.setLayerType(Layer.NETWORK);
		addr.LayerUnion = new UNION();
		
		addr.LayerUnion.Network = new WinDivertDataNetwork();
		addr.LayerUnion.Network.IfIdx = new WinDef.UINT(0);
		addr.LayerUnion.Network.SubIfIdx = new WinDef.UINT(0);
		
		addr.setIsImposter(imposter);
		
		addr.setIsIPChecksum(validIpChecksum);
		addr.setIsTCPChecksum(validTcpChecksum);
		addr.setIsUDPChecksum(validUdpChecksum);
		
		return addr;
	}
	
	private int getValue(int offset, int mask) {
		return (data1.intValue() >> offset) & mask;
	}
	
	private void setValue(int offset, int mask, int value) {
		mask = ~(mask << offset);
		long result = data1.longValue() & mask;
		result = result | (value << offset);
		data1.setValue(result);
	}
	
	public Enums.Layer getLayerType() {
		return Enums.Layer.getInstance(getValue(LAYER_OFFSET, 0xFF));
	}
	
	public void setLayerType(Enums.Layer layer) {
		setValue(LAYER_OFFSET, 0xFF, layer.getValue());
	}
	
	public Enums.Event getEventType() {
		return Enums.Event.getInstance(getValue(EVENT_OFFSET, 0xFF));
	}
	
	public void setEventType(Enums.Event event) {
		setValue(EVENT_OFFSET, 0xFF, event.getValue());
	}
	
	public boolean isSniffed() {
		return getValue(SNIFFED_OFFSET, 1) == 1 ? true : false;
	}
	
	public void setIsSniffed(boolean sniffed) {
		setValue(SNIFFED_OFFSET, 1, sniffed ? 1 : 0);
	}
	
	public void setIsOutbound(boolean outbound) {
		setValue(OUTBOUND_OFFSET, 1, outbound ? 1 : 0);
	}
	
	public boolean isOutbound() {
		return getValue(OUTBOUND_OFFSET, 1) == 1 ? true : false;
	}
	
	public boolean isInbound() {
		return !isOutbound();
	}
	
	public boolean isLoopback() {
		return getValue(LOOPBACK_OFFSET, 1) == 1 ? true : false;
	}
	
	public void setIsLoopback(boolean loopback) {
		setValue(LOOPBACK_OFFSET, 1, loopback ? 1 : 0);
	}
	
	public boolean isImposter() {
		return getValue(IMPOSTER_OFFSET, 1) == 1 ? true : false;
	}
	
	public void setIsImposter(boolean imposter) {
		setValue(IMPOSTER_OFFSET, 1, imposter ? 1 : 0);
	}
	
	public boolean isIPv6() {
		return getValue(IPV6_OFFSET, 1) == 1 ? true : false;
	}
	
	public void setIsIPv6(boolean ipv6) {
		setValue(IPV6_OFFSET, 1, ipv6 ? 1 : 0);
	}
	
	public boolean isIPChecksum() {
		return getValue(IPCHECKSUM_OFFSET, 1) == 1 ? true : false;
	}
	
	public void setIsIPChecksum(boolean ipchecksum) {
		setValue(IPCHECKSUM_OFFSET, 1, ipchecksum ? 1 : 0);
	}
	
	public boolean isTCPChecksum() {
		return getValue(TCPCHECKSUM_OFFSET, 1) == 1 ? true : false;
	}
	
	public void setIsTCPChecksum(boolean tcpchecksum) {
		setValue(TCPCHECKSUM_OFFSET, 1, tcpchecksum ? 1 : 0);
	}
	
	public boolean isUDPChecksum() {
		return getValue(UDPCHECKSUM_OFFSET, 1) == 1 ? true : false;
	}
	
	public void setIsUDPChecksum(boolean udpchecksum) {
		setValue(UDPCHECKSUM_OFFSET, 1, udpchecksum ? 1 : 0);
	}

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("timestamp",
                "data1",
                "reserved2",
                "LayerUnion");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || !(o instanceof WinDivertAddress)) return false;

        WinDivertAddress that = (WinDivertAddress) o;

        return timestamp.longValue() == that.timestamp.longValue() &&
        		data1.intValue() == that.data1.intValue() &&
        		LayerUnion == null ? (that.LayerUnion == null) : LayerUnion.equals(that.LayerUnion);
    }

    @Override
    public int hashCode() {
        return Objects.hash(timestamp, data1, LayerUnion);
    }
}