package burp.task;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.impl.VulTaskImpl;

import java.util.ArrayList;
import java.util.List;

public class XmlMaybe extends VulTaskImpl {

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new XmlMaybe(helpers, callbacks, log);
    }
    private XmlMaybe(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
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
        if (!isStaticSource(path, new ArrayList<>())){
            if (request_body_str.length() > 0){
                //contenttype是xml的
                String ct = check(request_header_list, "content-type");
                if ( ct != null && ct.contains("application/xml")) {
                    message += "XmlData";
                }else if (check(request_header_list, "multipart/form-data") != null){//上传xml文件
                    if (request_body_str.contains("application/xml")){
                        message += "XmlData-Upload";
                    }
                }
            }
            if (!message.equalsIgnoreCase("")) {
                //不需要发包,上面正则匹配到则存在问题
                logAdd(messageInfo, host, path, method, status, message, payloads);
            }
        }
    }

}
