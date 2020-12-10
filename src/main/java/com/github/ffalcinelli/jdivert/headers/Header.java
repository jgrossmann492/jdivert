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

package com.github.ffalcinelli.jdivert.headers;

import com.github.ffalcinelli.jdivert.Util;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static java.nio.ByteOrder.BIG_ENDIAN;

/**
 * A Network Header
 * Created by fabio on 24/10/2016.
 */
public abstract class Header {


    protected ByteBuffer raw;
    protected int start;
    protected boolean hasPorts;

    public Header(ByteBuffer raw) {
        this(raw, 0, true);
    }
    
    public Header(ByteBuffer raw, boolean duplicateBuffer) {
    	this(raw, 0, duplicateBuffer);
    }

    public Header(ByteBuffer raw, int start, boolean duplicateBuffer) {
        this.raw = duplicateBuffer ? raw.duplicate() : raw;
        this.raw.order(BIG_ENDIAN);
        this.start = start;
    }

    /**
     * Build headers from raw data.
     *
     * @param data The data's array of bytes
     * @param duplicateBuffer	Whether to duplicate the raw data buffer stored in this object
     * @return A pair of headers, first of which is a {@link com.github.ffalcinelli.jdivert.headers.Ip} header while the second
     * is either a {@link com.github.ffalcinelli.jdivert.headers.Transport} or {@link com.github.ffalcinelli.jdivert.headers.Icmp} header
     */
    public static Header[] buildHeaders(byte[] data, boolean duplicateBuffer) {
        ByteBuffer raw = ByteBuffer.wrap(data);
        raw.order(BIG_ENDIAN);
        Ip ipHdr;
        Header[] headers = new Header[2];
        if (Ip.getVersion(raw) == 4) {
            ipHdr = new Ipv4(raw);
        } else {
            ipHdr = new Ipv6(raw);
        }
        headers[0] = ipHdr;
        switch (ipHdr.getNextHeaderProtocol()) {
            case TCP:
                headers[1] = new Tcp(raw, ipHdr, ipHdr.getHeaderLength(), duplicateBuffer);
                break;
            case UDP:
                headers[1] = new Udp(raw, ipHdr, ipHdr.getHeaderLength(), duplicateBuffer);
                break;
            case ICMP:
                headers[1] = new Icmpv4(raw, ipHdr.getHeaderLength(), duplicateBuffer);
                break;
            case ICMPV6:
                headers[1] = new Icmpv6(raw, ipHdr.getHeaderLength(), duplicateBuffer);
        }
        return headers;
    }
    
    public static Header[] buildHeaders(byte[] data) {
    	return buildHeaders(data, false);
    }
    
    /**
     * Convenience method to check if the protocol header contains ports
     * @return Whether this header contains ports
     */
    public boolean hasPorts() {
    	return hasPorts;
    }
    
    /**
     * Convenience method to set if the protocol header contains ports
     * @param hasPorts	Whether this header contains ports
     */
    public void setHasPorts(boolean hasPorts) {
    	this.hasPorts = hasPorts;
    }

    /**
     * Convenience method to get a given range of bytes
     *
     * @param offset The starting offset
     * @param length How many bytes to read
     * @return The byte array in range
     */
    public byte[] getBytesAtOffset(int offset, int length) {
        return Util.getBytesAtOffset(raw, offset, length);
    }

    /**
     * Convenience method to set an array of data
     *
     * @param offset The starting offset where to put data
     * @param length How many bytes to write
     * @param data   The data to write
     */
    public void setBytesAtOffset(int offset, int length, byte[] data) {
        Util.setBytesAtOffset(raw, offset, length, data);
    }

    /**
     * Convenience method to get the status of a flag (1 bit)
     *
     * @param index The byte index inside the buffer
     * @param pos   The flag position inside the byte (0-7)
     * @return True if the bit is 1, false if 0
     */
    public boolean getFlag(int index, int pos) {
        return (raw.get(index) & (1 << pos)) != 0;
    }

    /**
     * Convenience method to set the status of a flag (1 bit)
     *
     * @param index The byte index inside the buffer
     * @param pos   The flag position inside the byte (0-7)
     * @param flag  The value to assign: 1 if true else 0.
     */
    public void setFlag(int index, int pos, boolean flag) {
        int value = raw.get(index);
        if (flag)
            value |= 1 << pos;
        else
            value &= ~(1 << pos);
        raw.put(index, (byte) value);
    }

    /**
     * Get header's bytes only
     *
     * @return The byte array for this header
     */
    public byte[] getRawHeaderBytes() {
        return getBytesAtOffset(start, getHeaderLength());
    }

    /**
     * Return the Header length (in bytes).
     *
     * @return The header length (in bytes).
     */
    public abstract int getHeaderLength();


    /**
     * Return the {@link java.nio.ByteBuffer} used to construct this header
     *
     * @return The internal {@link java.nio.ByteBuffer}
     */
    public ByteBuffer getByteBuffer() {
        return raw;
    }
    
    public abstract void calculateChecksum();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Header header = (Header) o;
        return Arrays.equals(getRawHeaderBytes(), header.getRawHeaderBytes());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getRawHeaderBytes());
    }
}
