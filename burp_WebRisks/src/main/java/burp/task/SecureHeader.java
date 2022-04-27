package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class SecureHeader extends VulTaskImpl {

    public SecureHeader(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {

        // 后缀检查，静态资源不做测试
        if (isStaticSource(path)){
            return null;
        }

        List<String> headers = new ArrayList<String>();
//        headers.add("Strict-Transport-Securit"); // max-age=31536000;includeSubDomains;preload
        headers.add("X-Frame-Options"); // allow-from 'url'
//        headers.add("X-XSS-Protection"); // 1;mode=block
//        headers.add("X-Content-Type-Options"); // nosniff
//        headers.add("Content-Security-Policy");
        // 检查响应头是否包含安全响应头
        boolean without = true;
        for (String heaser :
                response_header_list) {
            for (String check :
                    headers) {
                    if (heaser.toLowerCase(Locale.ROOT).startsWith(check.toLowerCase(Locale.ROOT))) {
                        without = false;
                    }
                }
        }
        if (without){
            message = "without X-Frame-Options";
        }

        if (!message.equalsIgnoreCase("")){
            result = logAdd(messageInfo_r, host, path, method, status, message, payloads);
        }

        return result;
    }
}
