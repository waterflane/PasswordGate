package org.wodichka.passwordgate.storage;

import com.sun.jna.platform.win32.Crypt32Util;
import java.io.IOException;
import java.util.Locale;

final class WindowsDpapiProtector implements LocalKeyProtector {
    @Override public boolean available(){return System.getProperty("os.name","").toLowerCase(Locale.ROOT).contains("win");}
    @Override public byte[] protect(byte[] value)throws IOException{try{return Crypt32Util.cryptProtectData(value);}catch(RuntimeException|UnsatisfiedLinkError e){throw new IOException("Windows DPAPI is unavailable",e);}}
    @Override public byte[] unprotect(byte[] value)throws IOException{try{return Crypt32Util.cryptUnprotectData(value);}catch(RuntimeException|UnsatisfiedLinkError e){throw new IOException("Windows DPAPI could not unlock the key",e);}}
}
