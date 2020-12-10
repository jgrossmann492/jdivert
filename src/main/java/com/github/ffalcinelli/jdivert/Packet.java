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

package com.github.ffalcinelli.jdivert;

import com.github.ffalcinelli.jdivert.exceptions.WinDivertException;
import com.github.ffalcinelli.jdivert.headers.*;
import com.github.ffalcinelli.jdivert.windivert.WinDivertAddress;
import com.github.ffalcinelli.jdivert.windivert.WinDivertDLL;
import com.sun.jna.Memory;

import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import com.github.ffalcinelli.jdivert.Enums.Protocol;

import static com.github.ffalcinelli.jdivert.Util.printHexBinary;
import static com.github.ffalcinelli.jdivert.exceptions.WinDivertException.throwExceptionOnGetLastError;
import static com.sun.jna.platform.win32.WinDef.UINT;
import static com.sun.jna.platform.win32.WinDef.USHORT;

/**
 * A single packet, possibly including an {@link com.github.ffalcinelli.jdivert.headers.Ip} header,
 * a {@link com.github.ffalcinelli.jdivert.headers.Tcp}/{@link com.github.ffalcinelli.jdivert.headers.Udp} header and a payload.
 * <p>
 * Creation of packets is cheap, attributes are parsed when accessing them.
 * </p>
 * Created by fabio on 21/10/2016.
 */
public class Packet {

    private ByteBuffer raw;
    private Ip ipHdr;
    private Header protoHeader;
    private WinDivertAddress addr;

    /**
     * Construct a {@link Packet} from the given byte array and for the given metadata.
     *
     * @param raw       The packet's array of bytes.
     * @param addr		The WinDivertAddress helper object
     * @param duplicateBuffer	Indicate whether to duplicate the raw buffer stored in this object
     */
    public Packet(byte[] raw, WinDivertAddress addr, boolean duplicateBuffer) {
    	this.addr = addr;
        this.raw = ByteBuffer.wrap(raw);
        this.raw.order(ByteOrder.BIG_ENDIAN);
       
        for (Header header : Header.buildHeaders(raw, duplicateBuffer)) {
            if (header instanceof Ip) {
                ipHdr = (Ip) header;
            } else {
            	protoHeader = header;
            }
        }
    }
    
    public Packet(byte[] raw, WinDivertAddress addr) {
    	this(raw, addr, false);
    }

    /**
     * Convenience method to check if the packet has a {@link com.github.ffalcinelli.jdivert.headers.Ipv4 Ip header version 4}.
     *
     * @return True if packet is an Ipv4 one.
     */
    public boolean isIpv4() {
        return ipHdr.getVersion() == 4;
    }

    /**
     * Convenience method to check if the packet has a {@link com.github.ffalcinelli.jdivert.headers.Ipv6 Ip header version 6}.
     *
     * @return True if packet is an Ipv6 one.
     */
    public boolean isIpv6() {
        return ipHdr.getVersion() == 6;
    }

    /**
     * Convenience method to check if the packet has a {@link com.github.ffalcinelli.jdivert.headers.Icmpv4 Icmp header version 4}
     *
     * @return True if packet is an Icmpv4 one
     */
    public boolean isIcmpv4() {
    	return ipHdr.getNextHeaderProtocol() == Protocol.ICMP;
    }

    /**
     * Convenience method to check if the packet has a {@link com.github.ffalcinelli.jdivert.headers.Icmpv6 Icmp header version 6}.
     *
     * @return True if packet is an Icmpv6 one.
     */
    public boolean isIcmpv6() {
        return ipHdr.getNextHeaderProtocol() == Protocol.ICMPV6;
    }

    /**
     * Convenience method to check if the packet has a {@link com.github.ffalcinelli.jdivert.headers.Udp Udp header}.
     *
     * @return True if packet is an Udp one.
     */
    public boolean isUdp() {
        return ipHdr.getNextHeaderProtocol() == Protocol.UDP;
    }

    /**
     * Convenience method to check if the packet has a {@link com.github.ffalcinelli.jdivert.headers.Tcp Tcp header}.
     *
     * @return True if packet is an Tcp one.
     */
    public boolean isTcp() {
        return ipHdr.getNextHeaderProtocol() == Protocol.TCP;
    }

    /**
     * Convenience method to get the {@link com.github.ffalcinelli.jdivert.headers.Tcp} if present.
     *
     * @return The {@link com.github.ffalcinelli.jdivert.headers.Tcp} if present, {@code null} otherwise.
     */
    public Tcp getTcp() {
        return isTcp() ? (Tcp) protoHeader : null;
    }

    /**
     * Convenience method to get the {@link com.github.ffalcinelli.jdivert.headers.Udp} if present.
     *
     * @return The {@link com.github.ffalcinelli.jdivert.headers.Udp} if present, {@code null} otherwise.
     */
    public Udp getUdp() {
        return isUdp() ? (Udp) protoHeader : null;
    }

    /**
     * Convenience method to get the {@link com.github.ffalcinelli.jdivert.headers.Icmpv4} if present.
     *
     * @return The {@link com.github.ffalcinelli.jdivert.headers.Icmpv4} if present, {@code null} otherwise.
     */
    public Icmpv4 getIcmpv4() {
        return isIcmpv4() ? (Icmpv4) protoHeader : null;
    }

    /**
     * Convenience method to get the {@link com.github.ffalcinelli.jdivert.headers.Icmpv6} if present.
     *
     * @return The {@link com.github.ffalcinelli.jdivert.headers.Icmpv6} if present, {@code null} otherwise.
     */
    public Icmpv6 getIcmpv6() {
        return isIcmpv6() ? (Icmpv6) protoHeader : null;
    }

    /**
     * Convenience method to get the {@link com.github.ffalcinelli.jdivert.headers.Ipv4} if present.
     *
     * @return The {@link com.github.ffalcinelli.jdivert.headers.Ipv4} if present, {@code null} otherwise.
     */
    public Ipv4 getIpv4() {
        return isIpv4() ? (Ipv4) ipHdr : null;
    }

    /**
     * Convenience method to get the {@link com.github.ffalcinelli.jdivert.headers.Ipv6} if present.
     *
     * @return The {@link com.github.ffalcinelli.jdivert.headers.Ipv6} if present, {@code null} otherwise.
     */
    public Ipv6 getIpv6() {
        return isIpv6() ? (Ipv6) ipHdr : null;
    }
    
    public Ip getIpHeader() {
    	return ipHdr;
    }
    
    public Header getProtocolHeader() {
    	return this.protoHeader;
    }

    /**
     * Convenience method to get the String representing the source address.
     *
     * @return The source address String.
     */
    public String getSrcAddr() {
        return ipHdr.getSrcAddrStr();
    }

    /**
     * Convenience method to set the source address.
     *
     * @param address The String representing the source address to set.
     * @throws UnknownHostException Unlikely to be thrown...
     */
    public void setSrcAddr(String address) throws UnknownHostException {
        ipHdr.setSrcAddrStr(address);
    }

    /**
     * Convenience method to get the String representing the destination address.
     *
     * @return The destination address String.
     */
    public String getDstAddr() {
        return ipHdr.getDstAddrStr();
    }

    /**
     * Convenience method to set the destination address.
     *
     * @param address The String representing the destination address to set.
     * @throws UnknownHostException Unlikely to be thrown...
     */
    public void setDstAddr(String address) throws UnknownHostException {
        ipHdr.setDstAddrStr(address);
    }

    /**
     * Convenience method to get the source port number, if present.
     *
     * @return The source port number if present, {@code null} otherwise.
     */
    public Integer getSrcPort() {
        return protoHeader.hasPorts() ? ((Transport) protoHeader).getSrcPort() : null;
    }

    /**
     * Convenience method to set the source port number.
     *
     * @param port The port number to set for source service. If packet does not have such info an {@link java.lang.IllegalStateException} is thrown.
     */
    public void setSrcPort(int port) {
        if (protoHeader.hasPorts())
            ((Transport) protoHeader).setSrcPort(port);
        else
            throw new IllegalStateException("A port number cannot be set");
    }

    /**
     * Convenience method to get the destination port number, if present.
     *
     * @return The destination port number if present, {@code null} otherwise.
     */
    public Integer getDstPort() {
        return protoHeader.hasPorts() ? ((Transport) protoHeader).getDstPort() : null;
    }

    /**
     * Convenience method to set the destination port number.
     *
     * @param port The port number to set for destination service. If packet does not have such info an {@link java.lang.IllegalStateException} is thrown.
     */
    public void setDstPort(int port) {
        if (protoHeader.hasPorts())
            ((Transport) protoHeader).setDstPort(port);
        else
            throw new IllegalStateException("A port number cannot be set");
    }

    /**
     * Get the {@link Packet} payload.
     *
     * @return The payload's array of bytes.
     */
    public byte[] getPayload() {
        return Util.getBytesAtOffset(raw, getHeadersLength(), raw.capacity() - getHeadersLength());
    }

    /**
     * Sets the given byte array as {@link Packet} payload.
     *
     * @param payload The byte array to use as payload.
     */
    public void setPayload(byte[] payload) {
        //TODO: adjust length!
    	System.out.println("headers offset: "+getHeadersLength());
    	System.out.println("total length: "+raw.capacity());
    	System.out.println("payload length: "+payload.length);
        Util.setBytesAtOffset(raw, getHeadersLength(), payload.length, payload);
    }

    /**
     * Overall {@link Packet}'s header length.
     * @return The overall {@link Packet} headers length
     */
    public int getHeadersLength() {
    	return ipHdr.getHeaderLength() + protoHeader.getHeaderLength();
    }

    /**
     * Get the {@link Packet} content (headers and payload) as an array of bytes.
     * @param copy Whether to copy the stored raw data or return the raw data as is
     * @return The packet's array of bytes.
     */
    public byte[] getRaw(boolean copy) {
        return copy ? Util.getBytesAtOffset(raw, 0, raw.capacity()) : raw.array();
    }

    /**
     * Put the {@link Packet} metadata into a {@link com.github.ffalcinelli.jdivert.windivert.WinDivertAddress} structure.
     *
     * @return The {@link com.github.ffalcinelli.jdivert.windivert.WinDivertAddress} representing the packet metadata.
     */
    public WinDivertAddress getWinDivertAddress() {
        return addr;
    }
    
    public void calculateAllCheckSumsLocal() {    	    	
    	protoHeader.calculateChecksum();
    	ipHdr.calculateChecksum();
    }
    

    @Override
    public String toString() {
        return String.format("Packet {%s, %s, %s, raw=%s}"
                , ipHdr
                , protoHeader
                , addr
                , printHexBinary(getRaw(false))
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Packet packet = (Packet) o;
        return Arrays.equals(raw.array(), packet.raw.array()) &&
                getWinDivertAddress().equals(packet.getWinDivertAddress());
    }


    @Override
    public int hashCode() {
        int result = Arrays.hashCode(raw.array());
        result = 31 * result + getWinDivertAddress().hashCode();
        return result;
    }

}
