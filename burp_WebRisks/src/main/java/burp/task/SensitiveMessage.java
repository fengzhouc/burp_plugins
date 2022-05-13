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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SensitiveMessage extends VulTaskImpl {

    public SensitiveMessage(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 检测逻辑
         * 检测响应匹配正则
         * */

        // 后缀检查，静态资源不做测试
        if (isStaticSource(path, new ArrayList<>())){
            return null;
        }

        //如果有响应才检测
        if (resp_body_str.length() > 0){
            //先检测是否存在url地址的参数，正则匹配
            String UIDRegex = "[1-9]\\d{5}(18|19|([23]\\d))\\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\\d{3}[0-9Xx]"; //身份证的正则
            String phoneRegex = "((13[0-9])|(15[^4,\\D])|(18[0,5-9]))\\d{8}"; //手机号的正则
            String emailRegex = "\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*"; //邮箱的正则
            Pattern patternUID = Pattern.compile(UIDRegex);
            Pattern patternPhone = Pattern.compile(phoneRegex);
            Pattern patternEmail = Pattern.compile(emailRegex);
            Matcher matcherUid = patternUID.matcher(resp_body_str);
            Matcher matcherPhone = patternPhone.matcher(resp_body_str);
            Matcher matcherEmail = patternEmail.matcher(resp_body_str);
            if (!matcherUid.find()){//没匹配到则不进行后续验证
                return null;
            }else if (!matcherPhone.find()){
                return null;
            }else if (!matcherEmail.find()){
                return null;
            }
            //不需要发包,上面正则匹配到则存在问题
            logAdd(messageInfo, host, path, method, status, "SensitiveMessage", "");
        }
        return result;
    }

}

class SensitiveMessageCallback implements Callback {

    VulTaskImpl vulTask;

    public SensitiveMessageCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[SensitiveMessageCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
        // 检查响应中是否存在flag
        if (vulTask.ok_respBody.contains("evil6666.com")) {
            vulTask.message = "SSRF";
            vulTask.log(call);
        }else if (response.isSuccessful()){
            // 可能响应并没有回馈，所以这时响应是成功的也告警
            vulTask.message = "SSRF, Not in Resp";
            vulTask.log(call);
        }
    }
}