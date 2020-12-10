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

import java.util.HashMap;

/**
 * Created by fabio on 20/10/2016.
 */
public class Enums {

    /**
     * See <a href="https://reqrypt.org/windivert-doc.html#divert_layers">https://reqrypt.org/windivert-doc.html#divert_layers</a>.
     */
    public enum Layer {
        /**
         * The headers layer. This is the default.
         */
        NETWORK(0),
        /**
         * The headers layer (forwarded packets).
         */
        NETWORK_FORWARD(1),
    	
    	FLOW(2),
    	
    	SOCKET(3),
    	
    	REFLECT(4);
    	
    	
    	private static final Layer[] LayerLookup = createLayerLookup();
    	
    	private static Layer[] createLayerLookup() {
    		Layer[] allLayers = Layer.values();
    		Layer[] lookup = new Layer[allLayers.length];
    		for(Layer l : allLayers) {
    			lookup[l.getValue()] = l;
    		}
    		return lookup;
    	}
    	
        private int value;

        Layer(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
        
        public static Layer getInstance(int value) {
        	if(value < 0 || value >= LayerLookup.length) throw new IllegalArgumentException("No such Layer for value: "+value);
        	return LayerLookup[value];
        }
    }
    
    /**
     * See <a href="https://reqrypt.org/windivert-doc.html#divert_events">https://reqrypt.org/windivert-doc.html#divert_events</a>
     */
    public enum Event {
    	NETWORK_PACKET(0),
    	FLOW_ESTABLISHED(1),
    	FLOW_DELETED(2),
    	SOCKET_BIND(3),
    	SOCKET_CONNECT(4),
    	SOCKET_LISTEN(5),
    	SOCKET_ACCEPT(6),
    	SOCKET_CLOSE(7),
    	REFLECT_OPEN(8),
    	REFLECT_CLOSE(9);
    	
    	private static final Event[] EventLookup = createEventLookup();
    	
    	private static Event[] createEventLookup() {
    		Event[] allEvents = Event.values();
    		Event[] lookup = new Event[allEvents.length];
    		for(Event e : allEvents) {
    			lookup[e.getValue()] = e;
    		}
    		return lookup;
    	}
    	
    	private int value;
    	Event(int value) {
    		this.value = value;
    	}
    	public int getValue() {
    		return value;
    	}
    	public static Event getInstance(int value) {
    		if(value < 0 || value >= EventLookup.length) throw new IllegalArgumentException("No such Event for value: "+value);
        	return EventLookup[value];
    	}
    }

    /**
     * See <a href="https://reqrypt.org/windivert-doc.html#divert_open">https://reqrypt.org/windivert-doc.html#divert_open</a>.
     */
    public enum Flag {
        DEFAULT(0),
        /**
         * This flag opens the WinDivert handle in packet sniffing mode. In packet sniffing mode the original packet is not dropped-and-diverted (the default) but copied-and-diverted. This mode is useful for implementing packet sniffing tools similar to those applications that currently use Winpcap.
         */
        SNIFF(1),
        /**
         * This flag indicates that the user application does not intend to read matching packets with WinDivertRecv(), instead the packets should be silently dropped. This is useful for implementing simple packet filters using the <a href="https://www.reqrypt.org/windivert-doc.html#filter_language">WinDivert filter language</a>.
         */
        DROP(2),
        
        RECV_ONLY(4),
        
        READ_ONLY(4),
        
        SEND_ONLY(8),
        
        WRITE_ONLY(8),
        
        NO_INSTALL(10),
        
        FRAGMENTS(20),
        
        /**
         * By default WinDivert ensures that each diverted packet has a valid checksum. If the checksum is missing (e.g. with Tcp checksum offloading), WinDivert will calculate it before passing the packet to the user application. This flag disables this behavior.
         */
        NO_CHECKSUM(1024);
        private int value;

        Flag(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    /**
     * See <a href="https://reqrypt.org/windivert-doc.html#divert_set_param">https://reqrypt.org/windivert-doc.html#divert_set_param</a>
     */
    public enum Param {
        /**
         * Sets the maximum length of the packet queue for {@link com.github.ffalcinelli.jdivert.windivert.WinDivert#recv()}. Currently the default value is 512 (actually 1024), the minimum is 1, and the maximum is 8192.
         */
        QUEUE_LEN(0, 32, 16384, 4096),
        /**
         * Sets the minimum time, in milliseconds, a packet can be queued before it is automatically dropped. Packets cannot be queued indefinitely, and ideally, packets should be processed by the application as soon as is possible. Note that this sets the minimum time a packet can be queued before it can be dropped. The actual time may be exceed this value. Currently the default value is 512, the minimum is 128, and the maximum is 2048.
         */
        QUEUE_TIME(1, 100, 16000, 2000),
        
        QUEUE_SIZE(2, 65535, 33554432, 4194304);
    	
        private int value;
        private int min;
        private int max;
        private int def;

        Param(int value, int min, int max, int def) {
            this.value = value;
            this.min = min;
            this.max = max;
            this.def = def;
        }

        public int getValue() {
            return value;
        }

        public int getMin() {
            return min;
        }

        public int getMax() {
            return max;
        }

        public int getDefault() {
            return def;
        }
    }

    /**
     * See <a href="https://reqrypt.org/windivert-doc.html#divert_address">https://reqrypt.org/windivert-doc.html#divert_address</a>
     */
    public enum Direction {
        OUTBOUND(0), INBOUND(1);
        private int value;

        Direction(int value) {
            this.value = value;
        }

        public static Direction fromValue(int value) {
            //works because values --> ordinal 0/1
            return Direction.values()[value];
        }

        public int getValue() {
            return value;
        }
    }
    
    public enum ShutdownType {
    	RECV(1),
    	SEND(2),
    	BOTH(3);
    	private int value;
    	private ShutdownType(int v) {
    		value = v;
    	}
    	public int getValue() {
    		return value;
    	}
    }
    
    /**
     * Checksum that you DO want to perform
     * @author John Grossmann
     *
     */
    public enum CalcChecksumsLocalOption {
    	IP_CHECKSUM, ICMP_CHECKSUM, ICMPV6_CHECKSUM, TCP_CHECKSUM, UDP_CHECKSUM;
    }

    /**
     * See <a href="https://reqrypt.org/windivert-doc.html#divert_helper_calc_checksums">https://reqrypt.org/windivert-doc.html#divert_helper_calc_checksums</a>
     */
    public enum CalcChecksumsOption {
        /**
         * Do not calculate the Ipv4 checksum.
         */
        NO_IP_CHECKSUM(1),
        /**
         * Do not calculate the Icmp checksum.
         */
        NO_ICMP_CHECKSUM(2),
        /**
         * Do not calculate the Icmpv6 checksum.
         */
        NO_ICMPV6_CHECKSUM(4),
        /**
         * Do not calculate the Tcp checksum.
         */
        NO_TCP_CHECKSUM(8),
        /**
         * Do not calculate the Udp checksum.
         */
        NO_UDP_CHECKSUM(16);
        private int value;

        CalcChecksumsOption(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    /**
     * Transport protocol values define the layout of the header that will immediately follow the IPv4 or IPv6 header.
     * See <a href="http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml">http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml</a>
     */
    public enum Protocol {
    	
        HOPOPT(0), ICMP(1), TCP(6), UDP(17), ROUTING(43), FRAGMENT(44), AH(51), ICMPV6(58), NONE(59), DSTOPTS(60);
    	
    	private static final HashMap<Integer, Protocol> protocolLookup = createProtocolLookup();
    	private static HashMap<Integer, Protocol> createProtocolLookup() {
    		HashMap<Integer, Protocol> map = new HashMap<Integer, Protocol>();
    		for (Protocol protocol : Protocol.values()) {
    			map.put(protocol.value, protocol);
            }
    		return map;
    	}
    	
        private int value;

        Protocol(int value) {
            this.value = value;
        }

        public static Protocol fromValue(int value) {
            Protocol p = protocolLookup.get(value);
            //if(p == null) throw new IllegalArgumentException(String.format("Protocol %d is not recognized", value));
            return p;
        }

        public int getValue() {
            return value;
        }
    }
}
