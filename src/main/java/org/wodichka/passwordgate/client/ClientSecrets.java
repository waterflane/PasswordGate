package org.wodichka.passwordgate.client;

import java.util.Arrays;

public final class ClientSecrets {
    private static char[] password;
    private ClientSecrets(){}
    public static synchronized void set(char[] value){clear();password=value.clone();}
    public static synchronized char[] copy(){return password==null?null:password.clone();}
    public static synchronized boolean present(){return password!=null&&password.length>0;}
    public static synchronized void clear(){if(password!=null)Arrays.fill(password,'\0');password=null;}
}
