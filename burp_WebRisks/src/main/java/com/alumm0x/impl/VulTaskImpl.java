package com.alumm0x.impl;

import burp.*;

import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.OkHttpRequester;
import com.alumm0x.util.Requester;
import com.alumm0x.util.ToolsUtil;

import java.util.*;

public abstract class VulTaskImpl extends Thread {
    
    public IHttpRequestResponse requestResponse;

    //发包器,单例模式
    protected Requester requester;
    protected OkHttpRequester okHttpRequester;

    public VulTaskImpl(IHttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse ;
        this.requester = Requester.getInstance(BurpExtender.callbacks, BurpExtender.helpers);
        this.okHttpRequester = OkHttpRequester.getInstance(BurpExtender.callbacks, BurpExtender.helpers);
    }

    // 后续可以持续更新这个后缀列表
    protected boolean isStaticSource(String path, List<String> add) {
        List<String> suffixs = new ArrayList<String>();
        suffixs.add(".css");
        suffixs.add(".gif");
        suffixs.add(".png");
        suffixs.add(".jpg");
        suffixs.add(".jpeg");
        suffixs.add(".woff");
        suffixs.add(".woff2");
        suffixs.add(".ico");
        suffixs.add(".svg");
        suffixs.add(".js.map"); // 前端js代码的请求后缀
        suffixs.addAll(add);
        suffixs.add("image/");//image/png,image/jpg等
        suffixs.add("text/css");
        suffixs.add("application/font-wof");
        String cententtype = ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "Content-type");
        for (String suffix :
                suffixs) {
            if (path.split("\\?")[0].endsWith(suffix)) { //防止查询参数影响后缀判断
                return true;
            }
            if (cententtype != null && cententtype.contains(suffix)){ //检查响应头
                return true;
            }
        }
        return false;
    }
}
