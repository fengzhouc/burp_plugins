package com.alumm0x.task;

import burp.*;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecureCookie extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new SecureCookie(requestResponse);
    }

    private SecureCookie(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        List<String> l = new ArrayList<>();
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            //检查响应头Cookie
            String setCookie = ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "Set-Cookie");
            if (setCookie != null && (!setCookie.toLowerCase(Locale.ROOT).contains("httponly"))){
                l.add("without httponly");
            }
            if (setCookie != null && !setCookie.toLowerCase(Locale.ROOT).contains("secure")) {
                l.add("without httponly");
            }
            // 默认domain为本域，如果设置了则判断下是否为子域
            if (setCookie.toLowerCase(Locale.ROOT).contains("domain=")){
                Pattern p = Pattern.compile("domain=(.*?);");
                Matcher matcher = p.matcher(setCookie);
                if (matcher.find()){
                    String d = matcher.group(1);
                    if (!BurpReqRespTools.getHost(requestResponse).toLowerCase(Locale.ROOT).endsWith(d.toLowerCase(Locale.ROOT))){
                        l.add("noSet secure");
                    }
                }
            }
            if (l.size() != 0){
                // 记录日志
                MainPanel.logAdd(
                    requestResponse, 
                    BurpReqRespTools.getHost(requestResponse), 
                    BurpReqRespTools.getUrlPath(requestResponse),
                    BurpReqRespTools.getMethod(requestResponse), 
                    BurpReqRespTools.getStatus(requestResponse), 
                    String.join(",", l), 
                    null);
            }
        }
    }
}