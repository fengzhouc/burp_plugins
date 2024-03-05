package burp.task;

import burp.*;
import burp.impl.VulTaskImpl;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class XssReflect extends VulTaskImpl {

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new XssReflect(helpers, callbacks, log);
    }
    private XssReflect(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、所有参数都添加特使flag
         * 2、然后检查响应头是否存在flag
         * */
        String xssflag = helpers.urlEncode("_<xss/>'\"flag");
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            payloads = loadPayloads("/payloads/XssReflect.bbm");

            //反射型只测查询参数
            String new_query = "";
            if (query != null)
            {
                new_query = createFormBody(query, xssflag);
            }else {
                // 没有查询参数的话，插入一个试试，为啥这个搞呢，有些会把url潜入到页面中，比如错误信息的时候，所以这时如果没有防护，那基本就存在问题的
                new_query = "test=" + xssflag;
            }
            //新的请求包
            okHttpRequester.send(url, method, request_header_list, new_query, request_body_str, contentYtpe, new XssReflectCallback(this));

        }
    }
}

class XssReflectCallback implements Callback {

    VulTaskImpl vulTask;

    public XssReflectCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[XssReflectCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
        String ct = vulTask.ok_respHeaders.get("Content-Type");
        // 反射性仅存在于响应content-type是页面等会被浏览器渲染的资源，比如json响应是没有的，有也是dom型
        if(ct != null && (
            ct.contains("text/html") 
            || ct.contains("application/xhtml+xml")
            || ct.contains("application/x-www-form-urlencoded")
            || ct.contains("image/svg+xml")
            )){
            // 检查响应中是否存在flag
            if (vulTask.ok_respBody.contains("_<xss/>'\"flag")) {
                vulTask.message = "XssReflect";
                vulTask.log(call);
            }
        }
    }
}