package burp.vuls;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import java.util.List;

public class Struts {

    public static IExtensionHelpers helpers;
    public static IBurpExtenderCallbacks callbacks;
    public static List<BurpExtender.LogEntry> log;
    public static IHttpRequestResponse messageInfo;

    public static void CVE_2019_0230(){
        // TODO 待完成
        log.add(new BurpExtender.LogEntry(log.size(), callbacks.saveBuffersToTempFiles(messageInfo), "", "", "", (short) 200, ""));
    }

}
