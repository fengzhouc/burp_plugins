package burp.task;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class XssDomSource extends VulTaskImpl {

    public XssDomSource(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
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
        if (isStaticSource(path, new ArrayList<>())){
            return null;
        }
        payloads = loadPayloads("/payloads/XssDomSourceSink.bbm");

        if (resp_body_str.contains("window.location.hash")) {
            message += ",window.location.hash";
        }
        if (resp_body_str.contains("window.location.pathname")) {
            message += ",window.location.pathname";
        }
        if (resp_body_str.contains("window.location.href")) {
            message += ",window.location.href";
        }
        if (resp_body_str.contains("window.location.hash")) {
            message += ",window.location.hash";
        }
        if (resp_body_str.contains("window.location.search")) {
            message += ",window.location.search";
        }
        if (resp_body_str.contains("document.documentURI")) {
            message += ",document.documentURI";
        }
        if (resp_body_str.contains("document.baseURI")) {
            message += ",document.baseURI";
        }
        if (resp_body_str.contains("document.referrer")) {
            message += ",document.referrer";
        }

        if (!message.equalsIgnoreCase("")) {
            //不需要发包,上面正则匹配到则存在问题
            logAdd(messageInfo, host, path, method, status, message, payloads);
        }
        return result;
    }
}
