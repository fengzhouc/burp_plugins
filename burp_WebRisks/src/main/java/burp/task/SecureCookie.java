package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecureCookie extends VulTaskImpl {
    // 检查cookie安全属性httponly、secure、doomain

    public SecureCookie(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        // 后缀检查，静态资源不做测试
        if (isStaticSource(path)){
            return null;
        }

        for (String heaser :
                response_header_list) {
                if (heaser.toLowerCase(Locale.ROOT).startsWith("Set-Cookie".toLowerCase(Locale.ROOT))) {
                    if (!heaser.toLowerCase(Locale.ROOT).contains("httponly") || !heaser.toLowerCase(Locale.ROOT).contains("secure")){
                        message = "without httponly or secure";
                    }
                    // 默认domain为本域，如果设置了则判断下是否为子域
                    if (heaser.toLowerCase(Locale.ROOT).contains("domain=")){
                        Pattern p = Pattern.compile("domain=(.*?);");
                        Matcher matcher = p.matcher(heaser);
                        if (matcher.find()){
                            String d = matcher.group(1);
                            if (!host.toLowerCase(Locale.ROOT).contains(d.toLowerCase(Locale.ROOT))){
                                message += ", domain no secure";
                            }
                        }
                    }
                }
        }

        if (!message.equalsIgnoreCase("")){
            result = logAdd(messageInfo_r, host, path, method, status_code, message, "");
        }

        return result;
    }
}
