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

package com.github.ffalcinelli.jdivert.network;

import org.junit.Before;
import org.junit.Test;

import static com.github.ffalcinelli.jdivert.Consts.Protocol.ICMP;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * Created by fabio on 02/11/2016.
 */
public class ICMPIPv4HeaderTestCase extends IPv4IPHeaderTestCase {

    protected ICMPv4Header icmpHdr;
    protected byte[] restOfHeader;

    @Before
    public void setUp() {
        rawDataHexString = "4500005426ef0000400157f9c0a82b09080808080800bbb3d73b000051a7d67d000451e408090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637";
        super.setUp();
        icmpHdr = new ICMPv4Header(ipHdr.getRaw(), ipHdr.getHeaderLength());
        srcAddr = "192.168.43.9";
        dstAddr = "8.8.8.8";
        protocol = ICMP;
        ipHeaderLength = 20;
        ident = 9967;
        ipCksum = 22521;
        restOfHeader = new byte[]{-41, 59, 0x0, 0x0};
    }

    @Test
    public void buildHeadersBis() {
        Header[] headers = Header.buildHeaders(rawData);
        assertEquals(icmpHdr, headers[1]);
    }

    @Test
    public void type() {
        assertEquals(8, icmpHdr.getType());
        icmpHdr.setType((byte) 0xC);
        assertEquals((byte) 0xC, icmpHdr.getType());
    }

    @Test
    public void code() {
        assertEquals(0, icmpHdr.getCode());
        icmpHdr.setCode((byte) 0xC);
        assertEquals((byte) 0xC, icmpHdr.getCode());
    }

    @Test
    public void checksum() {
        super.checksum();
        assertEquals(48051, icmpHdr.getChecksum());
        icmpHdr.setChecksum(51234);
        assertEquals(51234, icmpHdr.getChecksum());
    }

    @Test
    public void restOfHeader() {
        assertArrayEquals(restOfHeader, icmpHdr.getRestOfHeader());
        byte[] data = new byte[]{0x0, 0x1, 0x2, 0x3};
        icmpHdr.setRestOfHeader(data);
        assertArrayEquals(data, icmpHdr.getRestOfHeader());
    }

}