package com.alumm0x.task.collect;

import burp.IHttpRequestResponse;

import java.util.ArrayList;
import java.util.List;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.SourceLoader;

public class XssDomSource extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new XssDomSource(requestResponse);
    }
    private XssDomSource(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1.检测js是否有引用常见的污染源
         * （1） window.location.hash
         * （2） window.location.href
         * （3） window.location.pathname
         * （4） window.location.search
         * （5） document.documentURI
         * （6） document.baseURI
         * （7） document.URL
         * （8） document.referrer
         * 2.但其实还要确认污染源被消费了才能真正确认存在domxss，这个burp这套没办法确认，需要污点分析啥的
         * */
        // 检查内嵌的json跟js中的
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), new ArrayList<>())){
            List<String> message = new ArrayList<>();
            String resp_body_str = new String(BurpReqRespTools.getRespBody(requestResponse));
            if (resp_body_str.contains("window.location.hash")) {
                message.add("window.location.hash");
            }
            if (resp_body_str.contains("window.location.pathname")) {
                message.add("window.location.pathname");
            }
            if (resp_body_str.contains("window.location.href")) {
                message.add("window.location.href");
            }
            if (resp_body_str.contains("window.location.hash")) {
                message.add("window.location.hash");
            }
            if (resp_body_str.contains("window.location.search")) {
                message.add("window.location.search");
            }
            if (resp_body_str.contains("document.documentURI")) {
                message.add("document.documentURI");
            }
            if (resp_body_str.contains("document.baseURI")) {
                message.add("document.baseURI");
            }
            if (resp_body_str.contains("document.referrer")) {
                message.add("document.referrer");
            }

            if (message.size() != 0) {
                //不需要发包,上面正则匹配到则存在问题
                // 记录日志
                MainPanel.logAdd(
                    requestResponse, 
                    BurpReqRespTools.getHost(requestResponse), 
                    BurpReqRespTools.getUrlPath(requestResponse),
                    BurpReqRespTools.getMethod(requestResponse), 
                    BurpReqRespTools.getStatus(requestResponse), 
                    XssDomSource.class.getSimpleName(),
                    String.join(",", message), 
                    String.join("\n", SourceLoader.loadSources("/payloads/XssDomSourceSink.bbm")));
            }
        }
    }
}
