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
import java.util.Arrays;
import java.util.List;


public class IndexOf extends VulTaskImpl {

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new IndexOf(helpers, callbacks, log);
    }

    private IndexOf(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        //只检测get请求
        if (method.equalsIgnoreCase("get")){
            //如果就是/，则直接检查响应
            if (resp_body_str.contains("Index of")) {
                message = "Index of /";
                result = logAdd(messageInfo_r, host, path, method, status_code, message, payloads);
            }else {
                //去掉最后一级path
                String[] q = path.split("/");
                StringBuilder p = new StringBuilder();
                for (int i = 0; i < q.length - 1; i++) {
                    if (!q[i].equalsIgnoreCase("")) {
                        p.append("/").append(q[i]);
                    }
                }
                p.append("/"); //如果没有会自动302，发包器默认不跟进
                this.path = p.toString(); //因为这里更改了请求的url，为了保持ui上显示一致
                this.url = iHttpService.getProtocol() + "://" + iHttpService.getHost() + ":" + iHttpService.getPort() + p;
                okHttpRequester.send(url, method, request_header_list, query, request_body_str, contentYtpe, new IndexOfCallback(this));
            }
        }
    }
}

class IndexOfCallback implements Callback {

    VulTaskImpl vulTask;

    public IndexOfCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[IndexOfCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            //如果状态码相同则可能存在问题
            if (vulTask.ok_respBody.contains("Index of")) {
                vulTask.message = "Index of ";
                vulTask.log(call);
            }

        }
    }
}