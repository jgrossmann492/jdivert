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

import java.nio.ByteBuffer;

import com.github.ffalcinelli.jdivert.Util;

import static com.github.ffalcinelli.jdivert.Util.unsigned;
import static com.github.ffalcinelli.jdivert.Util.zeroPadArray;
import static com.github.ffalcinelli.jdivert.headers.Tcp.Flag.NS;

/**
 * Created by fabio on 21/10/2016.
 */
public class Tcp extends Transport {

    public Tcp(ByteBuffer raw, Ip ipHdr, int offset, boolean duplicateBuffer) {
        super(raw, ipHdr, offset, duplicateBuffer);
    }
    
    public Tcp(ByteBuffer raw, Ip ipHdr, int offset) {
        super(raw, ipHdr, offset, false);
    }

    @Override
    public int getHeaderLength() {
        return getDataOffset() * 4;
    }

    public int getSeqNumber() {
        return raw.getInt(start + 4);
    }

    public void setSeqNumber(int seqNum) {
        raw.putInt(start + 4, seqNum);
    }

    public int getAckNumber() {
        return raw.getInt(start + 8);
    }

    public void setAckNumber(int ackNum) {
        raw.putInt(start + 8, ackNum);
    }

    public int getDataOffset() {
        return (raw.get(start + 12) & 0xF0) >> 4;
    }

    public void setDataOffset(int dataOffset) {
        if (dataOffset < 5 || dataOffset > 15)
            throw new IllegalArgumentException("TCP data offset must be greater or equal than 5 and less or equal than 15. You passed " + dataOffset);
        raw.put(start + 12, (byte) (((dataOffset << 4) | (getReserved() << 1) | (is(NS) ? 0x01 : 0x00))));
    }

    public int getReserved() {
        return (raw.get(start + 12) >> 1) & 0x07;
    }

    public void setReserved(int reserved) {
        raw.put(start + 12, (byte) ((getDataOffset() << 4) | (reserved << 1) | (is(NS) ? 0x01 : 0x00)));
    }
    
    public boolean isAny(Flag[] flags) {
    	for(Flag f : flags) if(is(f)) return true;
    	return false;
    }

    public boolean is(Flag flag) {
        if (flag == NS) {
            return getFlag(start + 12, 0);
        } else {
            //Starts by 8 since NS belongs to the previous byte
            return getFlag(start + 13, 8 - flag.ordinal());
        }
    }

    public void set(Flag flag, boolean value) {
        if (flag == NS) {
            setFlag(start + 12, 0, value);
        } else {
            //Starts by 8 since NS belongs to the previous byte
            setFlag(start + 13, 8 - flag.ordinal(), value);
        }
    }

    public int getFlags() {
        return raw.getShort(start + 12) & 0x01FF;
    }

    public void setFlags(int flags) {
        raw.putShort(start + 12, (short) ((getDataOffset() << 12) | (getReserved() << 5) | (flags & 0x01FF)));
    }

    public int getWindowSize() {
        return unsigned(raw.getShort(start + 14));
    }

    public void setWindowSize(int windowSize) {
        raw.putShort(start + 14, (short) windowSize);
    }

    public int getChecksum() {
        return unsigned(raw.getShort(start + 16));
    }

    public void setChecksum(int cksum) {
        raw.putShort(start + 16, (short) cksum);
    }

    public int getUrgentPointer() {
        return unsigned(raw.getShort(start + 18));
    }

    public void setUrgentPointer(int urgPtr) {
        raw.putShort(start + 18, (short) urgPtr);
    }
    
    public int getMSS() {
    	byte[] options = getOptions();
    	int index = 0;
    	
		while(index < options.length) {
			if(options[index] == 0x02) {
				ByteBuffer buff = ByteBuffer.allocate(2);
				buff.put(options[index+2]);
				buff.put(options[index+3]);
				buff.flip();
				return buff.getShort();
			}else if(options[index] == 0x01) {
				index++;
				continue;
			} else if(options[index] == 0x00) {
				return -1;
			} else {
				index += options[index+1];
			}
		}
		return -1;
    }

    public byte[] getOptions() {
        if (getHeaderLength() > 20)
            return getBytesAtOffset(start + 20, getHeaderLength() - 20);
        return null;
    }

    public void setOptions(byte[] options) {
        int delta = getHeaderLength() - 20;
        if (delta <= 0) {
            throw new IllegalStateException("Packet is too short for options.");
        }
        setBytesAtOffset(start + 20, delta, zeroPadArray(options, delta));
    }

    @Override
    public String toString() {
        StringBuilder flags = new StringBuilder();
        for (Flag flag : Flag.values()) {
            flags.append(flag).append("=").append(is(flag) ? 1 : 0).append(", ");
        }
        return String.format("TCP {srcPort=%d, dstPort=%d, seqNum=%d, ackNum=%d, dataOffset=%d, " +
                        "Reserved=%s, " +
                        "%s window=%d, cksum=%s, urgPtr=%d}"
                , getSrcPort()
                , getDstPort()
                , getSeqNumber()
                , getAckNumber()
                , getDataOffset()
                , Integer.toHexString(getReserved())
                , flags
                , getWindowSize()
                , Integer.toHexString(getChecksum())
                , getUrgentPointer()
        );
    }
    
    @Override
	public void calculateChecksum() {
		Util.computeChecksumLocal(raw.array(), start, start+16, raw.capacity(), ipHdr.getVirtualHeaderTotal());
	}
  

    public enum Flag {
        NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
    }
}
