package com.alumm0x.task.collect;

import burp.IHttpRequestResponse;

import java.util.ArrayList;
import java.util.List;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

public class XmlMaybe extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new XmlMaybe(requestResponse);
    }
    private XmlMaybe(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 检测请求提是否xml
         * */

        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), new ArrayList<>())){
            List<String> message = new ArrayList<>();
            String request_body_str = new String(BurpReqRespTools.getReqBody(requestResponse));
            if (request_body_str.length() > 0){
                //contenttype是xml的
                String ct = ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(requestResponse), "content-type");
                if ( ct != null && ct.contains("application/xml")) {
                    message.add("XmlData");
                }else if (ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(requestResponse), "multipart/form-data") != null){//上传xml文件
                    if (request_body_str.contains("application/xml")){
                        message.add("XmlData-Upload");
                    }
                }
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
                    XmlMaybe.class.getSimpleName(),
                    String.join(",", message), 
                    null);
            }
        }
    }

}
