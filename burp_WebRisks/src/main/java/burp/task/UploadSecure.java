package burp.task;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.impl.VulTaskImpl;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UploadSecure extends VulTaskImpl {

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new UploadSecure(helpers, callbacks, log);
    }
    private UploadSecure(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、修改文件名类型
         * 2、修改请求体中content-type的类型，有些是根据这里去设置文件类型的
         * */
        //限定contentype的头部为文件上传的类型
        if (contentYtpe.contains("multipart/form-data")){
            String fileName = "shell.php";
            //如果有body参数，需要多body参数进行测试
            if (request_body_str.length() > 0){
                //1.检查后缀名
                String regex = "filename=\"(.*?)\""; //分组获取文件名
                Pattern pattern = Pattern.compile(regex);
                Matcher matcher = pattern.matcher(request_body_str);
                if (matcher.find()){//没匹配到则不进行后续验证
                    String fileOrigin = matcher.group(1);
                    // 修改为别的域名
                    String req_body = request_body_str.replace(fileOrigin, fileName);
                    //新的请求包
                    okHttpRequester.send(url, method, request_header_list, query, req_body, contentYtpe, new UploadSecureCallback(this));
                    //2.修改content-type
                    String regex1 = "Content-Type:\\s(.*?)\\s"; //分组获取文件名
                    Pattern pattern1 = Pattern.compile(regex1);
                    Matcher matcher1 = pattern1.matcher(request_body_str);
                    if (!matcher1.find()){//没匹配到则不进行后续验证
                        String ctOrigin = matcher1.group(1);
                        // 修改为别的ct,在上面修改后缀的基础下
                        String req_body1 = req_body.replace(ctOrigin, "application/x-httpd-php");
                        //新的请求包
                        okHttpRequester.send(url, method, request_header_list, query, req_body1, contentYtpe, new UploadSecureCallback(this));
                    }
                }
            }
        }
    }

}

class UploadSecureCallback implements Callback {

    VulTaskImpl vulTask;

    public UploadSecureCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[UploadSecureCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            // 可能响应并没有回馈，所以这时响应是成功的也告警
            vulTask.message = "Upload";
            vulTask.log(call);
        }
    }
}