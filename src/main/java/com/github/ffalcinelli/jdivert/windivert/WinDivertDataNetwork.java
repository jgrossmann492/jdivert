package com.github.ffalcinelli.jdivert.windivert;

import java.util.Arrays;
import java.util.List;

import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef;

public class WinDivertDataNetwork extends Structure {
	
	public WinDef.UINT IfIdx;
	public WinDef.UINT SubIfIdx;
	
	
	@Override
	protected List getFieldOrder() {
		return Arrays.asList("IfIdx",
							"SubIfIdx");
	}
}
