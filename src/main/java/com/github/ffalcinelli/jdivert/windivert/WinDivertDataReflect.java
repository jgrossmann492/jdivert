package com.github.ffalcinelli.jdivert.windivert;

import java.util.Arrays;
import java.util.List;

import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef;

public class WinDivertDataReflect extends Structure {

	public WinDef.LONGLONG Timestamp;
	public WinDef.UINT ProcessId;
	public WinDef.UINT Layer;
	public WinDef.ULONGLONG Flags;
	public WinDef.SHORT Priority;
	
	@Override
	protected List getFieldOrder() {
		return Arrays.asList("Timestamp",
				"ProcessId",
				"Layer",
				"Flags",
				"Priority");
	}

}
