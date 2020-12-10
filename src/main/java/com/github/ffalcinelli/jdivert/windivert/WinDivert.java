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
import com.github.ffalcinelli.jdivert.Packet;
import com.github.ffalcinelli.jdivert.Util;
import com.github.ffalcinelli.jdivert.Enums.CalcChecksumsOption;
import com.github.ffalcinelli.jdivert.Enums.Flag;
import com.github.ffalcinelli.jdivert.Enums.Layer;
import com.github.ffalcinelli.jdivert.Enums.Param;
import com.github.ffalcinelli.jdivert.exceptions.WinDivertException;
import com.sun.jna.Memory;
import com.sun.jna.Structure;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import static com.github.ffalcinelli.jdivert.Enums.*;
import static com.github.ffalcinelli.jdivert.exceptions.WinDivertException.throwExceptionOnGetLastError;
import static com.sun.jna.platform.win32.WinNT.HANDLE;

/**
 * A WinDivert handle that can be used to capture packets.<p>
 * The main methods are {@link #open()}, {@link #recv()}, {@link #send(Packet)} and {@link #close()}.
 * </p>
 * Created by fabio on 20/10/2016.
 */
public class WinDivert {
	
    public static int DEFAULT_PACKET_BUFFER_SIZE = 1500;
    public static int DEFAULT_BATCH_MAX = 255;
    
    private WinDivertDLL dll = WinDivertDLL.INSTANCE;
    private String filter;
    private Layer layer;
    private int priority;
    private int flags;
    private HANDLE handle;
    
    private int sendBufferSize = DEFAULT_PACKET_BUFFER_SIZE;
    private int recvBufferSize = DEFAULT_PACKET_BUFFER_SIZE;
    
    private int maxBatchSendMessages = DEFAULT_BATCH_MAX;
    private int maxBatchRecvMessages = DEFAULT_BATCH_MAX;
    
    private boolean usePooledBuffers;
    private BlockingQueue<Memory> recvBufferQ;
    private BlockingQueue<Memory> sendBufferQ;
    
    private boolean useBatchPooledBuffers;
    private BlockingQueue<Memory> batchRecvBufferQ;
    private BlockingQueue<Memory> batchSendBufferQ;
    
    
    /**
     * Create a new WinDivert instance based upon the given filter for
     * {@link Enums.Layer#NETWORK NETWORK} layer with priority set to 0 and in
     * {@link Enums.Flag#DEFAULT DEFAULT} mode (Drop and divert packet).
     *
     * @param filter The filter string expressed using <a href="https://www.reqrypt.org/windivert-doc.html#filter_language">WinDivert filter language.</a>
     */
    public WinDivert(String filter) {
        this(filter, Layer.NETWORK, 0, Flag.DEFAULT);
    }


    /**
     * Create a new WinDivert instance based upon the given parameters
     *
     * @param filter   The filter string expressed using <a href="https://www.reqrypt.org/windivert-doc.html#filter_language">WinDivert filter language.</a>
     * @param layer    The {@link Enums.Layer layer}
     * @param priority The priority of the handle
     * @param flags    Additional {@link Enums.Flag flags}
     */
    public WinDivert(String filter, Layer layer, int priority, Flag... flags) {
        this.filter = filter;
        this.layer = layer;
        this.priority = priority;
        this.flags = 0;
        List<Flag> flagList = Arrays.asList(flags);
        if (flagList.contains(Flag.SNIFF) && flagList.contains(Flag.DROP)) {
            throw new IllegalArgumentException(String.format("A filter cannot be set with flags %s and %s at same time.", Flag.SNIFF, Flag.DROP));
        }
        for (Flag flag : flags) {
            this.flags |= flag.getValue();
        }

    }
    
    /**
     * Sets the size of the send buffers
     * @param size Size of the buffer
     */
    public void setSendBufferSize(int size) {
    	if(this.sendBufferSize == size) return;
    	
    	this.sendBufferSize = size;
    	if(this.usePooledBuffers) {
    		BlockingQueue<Memory> q = new ArrayBlockingQueue<Memory>(this.sendBufferQ.size());
    		for(int i = 0; i<sendBufferQ.size(); i++) q.add(new Memory(size));
    		this.sendBufferQ = q;
    	}
    }
    
    /**
     * Sets the size of the receive buffers
     * @param size Size of buffer
     */
    public void setRecvBufferSize(int size) {
    	if(this.recvBufferSize == size) return;
    	
    	this.recvBufferSize = size;
    	if(this.usePooledBuffers) {
    		BlockingQueue<Memory> q = new ArrayBlockingQueue<Memory>(this.recvBufferQ.size());
    		for(int i = 0; i<recvBufferQ.size(); i++) q.add(new Memory(size));
    		this.recvBufferQ = q;
    	}
    }
    
    public void setMaxRecvBatchMessages(int maxRecv) {
    	if(this.maxBatchRecvMessages == maxRecv) return;
    	
    	this.maxBatchRecvMessages = maxRecv;
    	if(this.useBatchPooledBuffers) {
    		BlockingQueue<Memory> q = new ArrayBlockingQueue<Memory>(this.batchRecvBufferQ.size());
    		int size = maxRecv * this.recvBufferSize;
    		for(int i = 0; i<batchRecvBufferQ.size(); i++) q.add(new Memory(size));
    		this.batchRecvBufferQ = q;
    	}
    }
    
    public void setMaxSendBatchMessages(int maxSend) {
    	if(this.maxBatchSendMessages == maxSend) return;
    	
    	this.maxBatchSendMessages = maxSend;
    	if(this.useBatchPooledBuffers) {
    		BlockingQueue<Memory> q = new ArrayBlockingQueue<Memory>(this.batchSendBufferQ.size());
    		int size = maxSend * this.sendBufferSize;
    		for(int i = 0; i<batchSendBufferQ.size(); i++) q.add(new Memory(size));
    		this.batchSendBufferQ = q;
    	}
    }
    
    public void setUseBatchPooledBuffers(boolean usePooled, int pooledRcv, int pooledSend, int maxRecvMessages, int maxSendMessages) {
    	if(this.useBatchPooledBuffers == usePooled) return;
    	
    	if(!usePooled) {
    		this.useBatchPooledBuffers = usePooled;
    		
    		this.batchRecvBufferQ = null;
    		this.batchSendBufferQ = null;
    	}
    	else {
    		if(pooledRcv < 1 || pooledSend < 1) throw new IllegalArgumentException("Number of pooled batch receive and pooled batch send memory buffers must be greater than 0");
    		if(maxRecvMessages < 1 || maxSendMessages < 1) throw new IllegalArgumentException("Max number of batch received messages and batch sent messages must be greater than 0");
    		
	    	this.batchRecvBufferQ = new ArrayBlockingQueue<Memory>(pooledRcv);
	    	for(int i = 0; i<pooledRcv; i++) batchRecvBufferQ.add(new Memory(this.recvBufferSize));
    		
	    	this.batchSendBufferQ = new ArrayBlockingQueue<Memory>(pooledSend);
	    	for(int i = 0; i<pooledSend; i++) batchSendBufferQ.add(new Memory(this.sendBufferSize));
	    	
	    	//must be set at the end of this if case to avoid nullpointer race condition with pooled queues being accessed.
	    	this.usePooledBuffers = usePooled;
    	}
    }
    
    /**
     * For efficient use of resources. This method creates a pool of Memory buffers to be reused when sending or receiving messages.
     * More efficient than creating a new memory buffer every call. For applications that use a single thread to send and a single thread to receive,
     * a send and receive pool of size 1 is sufficient. 
     * 
     * @param usePooled	True if you want to use pooled memory buffers, false otherwise
     * @param numRcv	Number of memory buffers for receiving messages	
     * @param numSend	Number of memory buffers for sending messages
     */
    public void setUsePooledBuffers(boolean usePooled, int numRcv, int numSend) {
    	if(this.usePooledBuffers == usePooled) return;
    	
    	if(!usePooled) {
    		//must be set at beginning of this if case to avoid nullpointer race condition with pooled queues being accessed
    		this.usePooledBuffers = usePooled;
    		
    		this.recvBufferQ = null;
    		this.sendBufferQ = null;
    	}else {
    		if(numRcv < 1 || numSend < 1) throw new IllegalArgumentException("Number of receive pooled buffers and send pooled buffers must be greater than 0");
    		
	    	this.recvBufferQ = new ArrayBlockingQueue<Memory>(numRcv);
	    	for(int i = 0; i<numRcv; i++) recvBufferQ.add(new Memory(this.recvBufferSize));
    		
	    	this.sendBufferQ = new ArrayBlockingQueue<Memory>(numSend);
	    	for(int i = 0; i<numSend; i++) sendBufferQ.add(new Memory(this.sendBufferSize));
	    	
	    	//must be set at the end of this if case to avoid nullpointer race condition with pooled queues being accessed.
	    	this.usePooledBuffers = usePooled;
    	}
    }
    
    private Memory getSendBuffer(int size) throws InterruptedException {
    	if(!this.usePooledBuffers || size > this.sendBufferSize) {
    		return new Memory(size);
    	}
    	else {
    		return this.sendBufferQ.take();
    	}
    }
    
    private Memory getRecvBuffer(int size) throws InterruptedException {
    	if(!this.usePooledBuffers || size > this.recvBufferSize) {
    		return new Memory(size);
    	}
    	else {
    		return this.recvBufferQ.take();
    	}
    }
    
    private void returnSendBuffer(Memory m) {
    	if(m.size() == this.sendBufferSize) {
    		this.sendBufferQ.add(m);
    	}
    }
    
    private void returnRecvBuffer(Memory m) {
    	if(m.size() == this.recvBufferSize) {
    		this.recvBufferQ.add(m);
    	}
    }
    
    private Memory getBatchSendBuffer(int numMessages) throws InterruptedException {
    	if(!this.useBatchPooledBuffers || numMessages > this.maxBatchSendMessages) {
    		return new Memory(numMessages * this.sendBufferSize);
    	}
    	else {
    		return this.batchSendBufferQ.take();
    	}
    }
    
    private Memory getBatchRecvBuffer(int numMessages) throws InterruptedException {
    	if(!this.useBatchPooledBuffers || numMessages > this.maxBatchRecvMessages) {
    		return new Memory(numMessages * this.recvBufferSize);
    	}
    	else {
    		return this.batchRecvBufferQ.take();
    	}
    }

    /**
     * Opens a WinDivert handle for the given filter.<br>
     * Unless otherwise specified by flags, any packet that matches the filter will be diverted to the handle.<br>
     * Diverted packets can be read by the application with {@link #recv() recv}.
     * <p>
     * The remapped function is {@code WinDivertOpen}:
     * </p>
     * <pre>{@code
     * HANDLE WinDivertOpen(
     *      __in const char *filter,
     *      __in WINDIVERT_LAYER layer,
     *      __in INT16 priority,
     *      __in UINT64 flags
     * );
     * }</pre>
     * <p>
     * For more info on the C call visit: <a href="http://reqrypt.org/windivert-doc.html#divert_open">http://reqrypt.org/windivert-doc.html#divert_open</a>
     *
     * @return this instance to allow call chaining (e.g. {@code Windivert w = new WinDivert("true").open()})
     * @throws WinDivertException Whenever the DLL call sets a LastError different by 0 (Success) or 997 (Overlapped I/O
     *                            is in progress)
     */
    public WinDivert open() throws WinDivertException {
        if (isOpen()) {
            throw new IllegalStateException("The instance is already in open state");
        }
        handle = dll.WinDivertOpen(filter, layer.getValue(), (short) priority, flags);
        throwExceptionOnGetLastError();
        //Allow call chaining
        return this;
    }

    /**
     * Indicates if there is currently an open handle.
     *
     * @return True if the handle is open, false otherwise
     */
    public boolean isOpen() {
        return handle != null;
    }

    /**
     * Closes the handle opened by {@link #open() open}.
     * <p>
     * The remapped function is {@code WinDivertClose}:
     * </p>
     * <pre>{@code
     * BOOL WinDivertClose(
     *      __in HANDLE handle
     * );
     * }</pre>
     * <p>
     * For more info on the C call visit: <a href="http://reqrypt.org/windivert-doc.html#divert_close">http://reqrypt.org/windivert-doc.html#divert_close</a>
     * """
     */
    public void close() {
        if (isOpen()) {
            dll.WinDivertClose(handle);
            handle = null;
        }
    }

    /**
     * Receives a diverted packet that matched the filter.<br>
     * The return value is a {@link com.github.ffalcinelli.jdivert.Packet packet}.
     * <p>
     * The remapped function is {@code WinDivertRecv}:
     * </p>
     * <pre>{@code
     * BOOL WinDivertRecv(
     *      __in HANDLE handle,
     *      __out PVOID pPacket,
     *      __in UINT packetLen,
     *      __out_opt PWINDIVERT_ADDRESS pAddr,
     *      __out_opt UINT *recvLen
     * );
     * }</pre>
     * <p>
     * For more info on the C call visit: <a href="http://reqrypt.org/windivert-doc.html#divert_recv">http://reqrypt.org/windivert-doc.html#divert_recv</a>
     *
     * @return A {@link com.github.ffalcinelli.jdivert.Packet Packet} instance
     * @throws WinDivertException Whenever the DLL call sets a LastError different by 0 (Success) or 997 (Overlapped I/O
     *                            is in progress)
     * @throws InterruptedException Only thrown if current thread is interrupted while waiting for a memory buffer from the pooled buffer queue.
     */
    public Packet recv() throws WinDivertException, InterruptedException {
        return recv(recvBufferSize);
    }

    /**
     * Receives a diverted packet that matched the filter.<br>
     * The return value is a {@link com.github.ffalcinelli.jdivert.Packet packet}.
     * <p>
     * The remapped function is {@code WinDivertRecv}:
     * </p>
     * <pre>{@code
     * BOOL WinDivertRecv(
     *      __in HANDLE handle,
     *      __out PVOID pPacket,
     *      __in UINT packetLen,
     *      __out_opt PWINDIVERT_ADDRESS pAddr,
     *      __out_opt UINT *recvLen
     * );
     * }</pre>
     * <p>
     * For more info on the C call visit: <a href="http://reqrypt.org/windivert-doc.html#divert_recv">http://reqrypt.org/windivert-doc.html#divert_recv</a>
     *
     * @param bufsize The size for the buffer to allocate
     * @return A {@link com.github.ffalcinelli.jdivert.Packet Packet} instance
     * @throws WinDivertException Whenever the DLL call sets a LastError different by 0 (Success) or 997 (Overlapped I/O
     *                            is in progress)
     * @throws InterruptedException Only thrown if current thread is interrupted while waiting for a memory buffer from the pooled buffer queue.
     */
    public Packet recv(int bufsize) throws WinDivertException, InterruptedException {
        WinDivertAddress address = new WinDivertAddress();
        Memory buffer = this.getRecvBuffer(bufsize);
        try {
	        IntByReference recvLen = new IntByReference();
	        
	        dll.WinDivertRecv(handle, buffer, bufsize, recvLen, address.getPointer());
	        throwExceptionOnGetLastError();
	        address.read();
	
	        return new Packet(buffer.getByteArray(0, recvLen.getValue()), address);
        }finally {
        	if(this.usePooledBuffers) this.returnRecvBuffer(buffer);
        }
    }
    
    public Packet[] recvEx() throws InterruptedException, WinDivertException {
    	return recvEx(this.maxBatchRecvMessages);
    }
    
    public Packet[] recvEx(int batchSize) throws InterruptedException, WinDivertException {    	
    	/*TODO pool arrays of windivertaddress to be used by batch processing only, then copy correct amount received after receive call*/
    	Structure[] addrArray = new WinDivertAddress().toArray(batchSize);
    	
    	Memory buffer = this.getBatchRecvBuffer(batchSize);
    	
    	IntByReference recvLen = new IntByReference();
    	IntByReference pAddrLen = new IntByReference(addrArray[0].size() * addrArray.length);
    	
    	dll.WinDivertRecvEx(handle, buffer, (int)buffer.size(), recvLen, 0L, addrArray[0].getPointer(), pAddrLen, null);
    	throwExceptionOnGetLastError();
    	
    	Packet[] packets = new Packet[pAddrLen.getValue()];
    	
    	/*int offset = 0;
    	for(int i = 0; i<packets.length; i++) {
    		WinDivertAddress addr = (WinDivertAddress) addrArray[i];
    		addr.read();
    		packets[i] = new Packet(buffer.getByteArray(offset, arraySize))
    	}*/
    	
    	return packets;
    }

    /**
     * Injects a packet into the headers stack.<br>
     * Recalculates the checksum before sending.<br>
     * The return value is the number of bytes actually sent.<br>
     * <p>
     * The injected packet may be one received from {@link com.github.ffalcinelli.jdivert.windivert.WinDivert#recv() recv}, or a modified version, or a completely new packet.
     * Injected packets can be captured and diverted again by other WinDivert handles with lower priorities.
     * </p><p>
     * The remapped function is {@code WinDivertSend}:
     * </p>
     * <pre>{@code
     * BOOL WinDivertSend(
     *      __in HANDLE handle,
     *      __in PVOID pPacket,
     *      __in UINT packetLen,
     *      __in PWINDIVERT_ADDRESS pAddr,
     *      __out_opt UINT *sendLen
     * );
     * }</pre>
     * <p>
     * For more info on the C call visit: <a href="http://reqrypt.org/windivert-doc.html#divert_send">http://reqrypt.org/windivert-doc.html#divert_send</a>
     *
     * @param packet The {@link com.github.ffalcinelli.jdivert.Packet Packet} to send
     * @return The number of bytes actually sent
     * @throws WinDivertException Whenever the DLL call sets a LastError different by 0 (Success) or 997 (Overlapped I/O
     *                            is in progress)
     * @throws InterruptedException Only thrown if current thread is interrupted while waiting for a memory buffer from the pooled buffer queue.
     */
    public int send(Packet packet) throws WinDivertException, InterruptedException {
        return send(packet, true);
    }

    /**
     * Injects a packet into the headers stack.<br>
     * Recalculates the checksum before sending unless {@code recalculateChecksum=false} is passed:<ul>
     * <li>If {@code recalculateChecksum=true} then checksums are calculated using the given {@link Enums.CalcChecksumsOption options}.</li>
     * <li>If {@code recalculateChecksum=false} then {@link Enums.CalcChecksumsOption options} are ignored.</li>
     * </ul>
     * The return value is the number of bytes actually sent.
     * <p>
     * The injected packet may be one received from {@link com.github.ffalcinelli.jdivert.windivert.WinDivert#recv() recv}, or a modified version, or a completely new packet.
     * Injected packets can be captured and diverted again by other WinDivert handles with lower priorities.
     * </p><p>
     * The remapped function is {@code WinDivertSend}:
     * </p>
     * <pre>{@code
     * BOOL WinDivertSend(
     *      __in HANDLE handle,
     *      __in PVOID pPacket,
     *      __in UINT packetLen,
     *      __in PWINDIVERT_ADDRESS pAddr,
     *      __out_opt UINT *sendLen
     * );
     * }</pre>
     * <p>
     * For more info on the C call visit: <a href="http://reqrypt.org/windivert-doc.html#divert_send">http://reqrypt.org/windivert-doc.html#divert_send</a>
     *
     * @param packet              The {@link com.github.ffalcinelli.jdivert.Packet Packet} to send
     * @param recalculateChecksum Whether to recalculate the checksums or pass the {@link com.github.ffalcinelli.jdivert.Packet packet} as is.
     * @param options             A set of {@link Enums.CalcChecksumsOption options} to use when recalculating checksums.
     * @return The number of bytes actually sent
     * @throws WinDivertException Whenever the DLL call sets a LastError different by 0 (Success) or 997 (Overlapped I/O
     *                            is in progress)
     * @throws InterruptedException Only thrown if current thread is interrupted while waiting for a memory buffer from the pooled buffer queue.
     */
    public int send(Packet packet, boolean recalculateChecksum, CalcChecksumsOption... options) throws WinDivertException, InterruptedException {
        if (recalculateChecksum) recalculateChecksum(packet, options);
        
        WinDivertAddress address = packet.getWinDivertAddress();
        IntByReference sendLen = new IntByReference();
        
        byte[] raw = packet.getRaw(false);
        Memory buffer = this.getSendBuffer(raw.length);
        try {
	        buffer.write(0, raw, 0, raw.length);
	        address.write();
	        
	        //System.out.println(address.toString());
	        
	        dll.WinDivertSend(handle, buffer, raw.length, sendLen, address.getPointer());
	        throwExceptionOnGetLastError();
	        
	        return sendLen.getValue();
        }finally {
        	if(this.usePooledBuffers) this.returnSendBuffer(buffer);
        }
    }

    /**
     * Get a WinDivert parameter. See {@link Enums.Param Param} for the list of parameters.
     * <p>
     * The remapped function is {@code WinDivertGetParam}:
     * </p>
     * <pre>{@code
     * BOOL WinDivertGetParam(
     *      __in HANDLE handle,
     *      __in WINDIVERT_PARAM param,
     *      __out UINT64 *pValue
     * );
     * }</pre>
     * <p>
     * For more info on the C call visit: <a href="http://reqrypt.org/windivert-doc.html#divert_get_param">http://reqrypt.org/windivert-doc.html#divert_get_param</a>
     *
     * @param param The {@link Enums.Param param} to set
     * @return The value for the parameter
     */
    public long getParam(Param param) {
        if (!isOpen()) {
            throw new IllegalStateException("WinDivert handle not in OPEN state");
        }
        LongByReference value = new LongByReference();
        dll.WinDivertGetParam(handle, param.getValue(), value);
        return value.getValue();
    }

    /**
     * Set a WinDivert parameter. See {@link Enums.Param Param} for the list of parameters.
     * <p>
     * The remapped function is {@code DivertSetParam}:
     * </p>
     * <pre>{@code
     * BOOL WinDivertSetParam(
     *      __in HANDLE handle,
     *      __in WINDIVERT_PARAM param,
     *      __in UINT64 value
     * );
     * }</pre>
     * <p>
     * For more info on the C call visit: <a href="http://reqrypt.org/windivert-doc.html#divert_set_param">http://reqrypt.org/windivert-doc.html#divert_set_param</a>
     *
     * @param param The {@link Enums.Param param} to set
     * @param value The value for the parameter
     */
    public void setParam(Param param, long value) {
        if (!isOpen()) {
            throw new IllegalStateException("WinDivert handle not in OPEN state");
        }
        if (param.getMin() > value || param.getMax() < value) {
            throw new IllegalArgumentException(String.format("%s must be in range %d, %d", param, param.getMin(), param.getMax()));
        }
        dll.WinDivertSetParam(handle, param.getValue(), value);
    }
    
    /**
     * Recalculates the checksum fields matching the given {@link Enums.CalcChecksumsOption options}.
     *
     * @param p Packet to calculate checksums for
     * @param options Drive the recalculateChecksum function.
     * @throws WinDivertException Whenever the DLL call sets a LastError different by 0 (Success) or 997 (Overlapped I/O
     *                            is in progress).
     */
    public static void recalculateChecksum(Packet p, Enums.CalcChecksumsOption... options) throws WinDivertException {
        long flags = 0;
        for (Enums.CalcChecksumsOption option : options) {
            flags |= option.getValue();
        }
        byte[] rawBytes = p.getRaw(false);
        Memory memory = new Memory(rawBytes.length);
        memory.write(0, rawBytes, 0, rawBytes.length);
        WinDivertDLL.INSTANCE.WinDivertHelperCalcChecksums(memory, rawBytes.length, null, flags);
        throwExceptionOnGetLastError();
        
        Util.setBytesAtOffset(ByteBuffer.wrap(rawBytes), 0, rawBytes.length,
                memory.getByteArray(0, rawBytes.length));
    }
    

    /**
     * Checks if the given flag is set
     *
     * @param flag The mode flag to set
     * @return True if the flag is set, false otherwise.
     */
    public boolean is(Flag flag) {
        return (flag.getValue() & flags) == flag.getValue();
    }

    /**
     * Returns the operational mode as a String
     *
     * @return String representation of the operational mode
     */
    public String getMode() {
        StringBuilder mode = new StringBuilder();
        for (Flag flag : Flag.values()) {
            if (is(flag)) {
                mode.append(flag).append("|");
            }
        }
        mode.deleteCharAt(mode.length() - 1);
        return mode.toString();
    }

    @Override
    public String toString() {

        return String.format("WinDivert{handle=%s, dll=%s, filter=%s, layer=%s, priority=%d, mode=%s, state=%s}"
                , handle
                , dll
                , filter
                , layer
                , priority
                , getMode()
                , isOpen() ? "OPEN" : "CLOSED"
        );
    }
}
