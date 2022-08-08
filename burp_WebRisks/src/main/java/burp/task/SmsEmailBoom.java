package burp.task;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.impl.VulTaskImpl;
import burp.util.CommonMess;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmsEmailBoom extends VulTaskImpl {

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new SmsEmailBoom(helpers, callbacks, log);
    }
    private SmsEmailBoom(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
        CommonMess.SmsEmailBoomCount = 0; //初始化为0
    }

    @Override
    public void run() {
        /**
         * 邮箱轰炸
         * */
        List<String> add = new ArrayList<String>();
        add.add(".js");
        // 后缀检查，静态资源不做测试
        if (!isStaticSource(path, add)){
            //如果请求参数中有邮箱，尝试下重放
            if (request_body_str.length() > 0 || query.length() > 0){
                //先检测是否存在url地址的参数，正则匹配
                String phoneRegex = "['\"&<;\\s/,=]+?1(3\\d|4[5-9]|5[0-35-9]|6[567]|7[0-8]|8\\d|9[0-35-9])\\d{8}['\"&<;\\s/,]?"; //手机号的正则
                String emailRegex = "\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*"; //邮箱的正则
                Pattern patternPhone = Pattern.compile(phoneRegex);
                Pattern patternEmail = Pattern.compile(emailRegex);
                Matcher matcherPhone_body = patternPhone.matcher(request_body_str);
                Matcher matcherPhone_query = patternPhone.matcher(query);
                Matcher matcherEmail_body = patternEmail.matcher(request_body_str);
                Matcher matcherEmail_query = patternEmail.matcher(query);
                if (matcherEmail_body.find() || matcherEmail_query.find()
                        || matcherPhone_body.find() || matcherPhone_query.find()){
                    for (int i = 0 ; i < 10 ; i++) { //重放10次
                        //新的请求包
                        okHttpRequester.send(url, method, request_header_list, query, request_body_str, contentYtpe, new SmsEmailBoomCallback(this));
                    }
                }
            }
        }
    }
}

class SmsEmailBoomCallback implements Callback {

    VulTaskImpl vulTask;

    public SmsEmailBoomCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[SmsEmailBoomCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            //如果状态码相同则可能存在问题
            if (vulTask.status == vulTask.ok_code
                    && vulTask.resp_body_str.equalsIgnoreCase(vulTask.ok_respBody)) {
                CommonMess.SmsEmailBoomCount += 1; //判断存在问题则次数+1
                if (CommonMess.SmsEmailBoomCount == 10) { //重放5次都判断有问题，则极大可能存在轰炸风险
                    vulTask.message = "SmsEmailBoom？？check device sms.";
                    vulTask.log(call);
                }
            }

        }
    }
}