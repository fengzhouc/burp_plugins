package com.alumm0x.task.config;

import burp.IHttpRequestResponse;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;

public class SourceMap extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new SourceMap(requestResponse);
    }
    private SourceMap(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测Javascript的源码泄漏，表现形式.js.map
         * */
        // 检查内嵌的json跟js中的
        if (BurpReqRespTools.getUrlPath(requestResponse).endsWith(".js.map")){
                // 记录日志
                MainPanel.logAdd(
                    requestResponse, 
                    BurpReqRespTools.getHost(requestResponse), 
                    BurpReqRespTools.getUrlPath(requestResponse),
                    BurpReqRespTools.getMethod(requestResponse), 
                    BurpReqRespTools.getStatus(requestResponse), 
                    SourceMap.class.getSimpleName(),
                    "leak the JavaScript Source Map.", 
                    null);
        }
    }
}
