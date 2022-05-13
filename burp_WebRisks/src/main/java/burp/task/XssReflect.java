package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;
import burp.util.HttpRequestResponseFactory;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class XssReflect extends VulTaskImpl {

    public XssReflect(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 检测逻辑
         * 1、所有参数都添加特使flag
         * 2、然后检查响应头是否存在flag
         * */
        String xssflag = "_xssflag";
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (isStaticSource(path, add)){
            return null;
        }
        payloads = loadPayloads("/payloads/XssReflect.bbm");

        //反射型只测查询参数
        if (query != null)
        {
            String new_query = createFormBody(query, xssflag);

            //新的请求包
            okHttpRequester.send(url, method, request_header_list, new_query, request_body_str, contentYtpe, new XssReflectCallback(this));
        }
        return result;
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
        // 检查响应中是否存在flag
        // TODO 关键字是否全
        if (vulTask.ok_respBody.contains("_xssflag")) {
            vulTask.message = "XssReflect";
            vulTask.log(call);
        }
    }
}