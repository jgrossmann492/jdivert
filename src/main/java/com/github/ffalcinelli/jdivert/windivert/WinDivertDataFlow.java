package com.github.ffalcinelli.jdivert.windivert;

import java.util.Arrays;
import java.util.List;

import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef;

public class WinDivertDataFlow extends Structure {

	public WinDef.ULONGLONG Endpoint;
	public WinDef.ULONGLONG ParentEndpoint;
	public WinDef.UINT ProcessId;
	public WinDef.UINT[] LocalAddr = new WinDef.UINT[4];
	public WinDef.UINT[] RemoteAddr = new WinDef.UINT[4];
	public WinDef.USHORT LocalPort;
	public WinDef.USHORT RemotePort;
	public WinDef.UCHAR Protocol;
	
	@Override
	protected List getFieldOrder() {
		return Arrays.asList("Endpoint",
				"ParentEndpoint",
				"ProcessId",
				"LocalAddr",
				"RemoteAddr",
				"LocalPort",
				"RemotePort",
				"Protocol");
	}

}
