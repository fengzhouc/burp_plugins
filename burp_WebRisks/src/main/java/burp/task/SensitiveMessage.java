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

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new SensitiveMessage(helpers, callbacks, log);
    }
    private SensitiveMessage(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 检测响应匹配正则
         * */

        // 后缀检查，静态资源不做测试
        if (!isStaticSource(path, new ArrayList<>())){
            payloads = loadPayloads("/payloads/SensitiveMessageRegex.bbm");
            //如果有响应才检测
            if (resp_body_str.length() > 0){
                //先检测是否存在url地址的参数，正则匹配
                String UIDRegex = "['\"&<;\\s/,][1-9]\\d{5}(18|19|([23]\\d))\\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\\d{3}[0-9Xx]['\"&<;\\s/,]"; //身份证的正则
                String phoneRegex = "['\"&<;\\s/,]+?1(3\\d|4[5-9]|5[0-35-9]|6[567]|7[0-8]|8\\d|9[0-35-9])\\d{8}['\"&<;\\s/,]+?"; //手机号的正则
                String emailRegex = "\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*"; //邮箱的正则
                Pattern patternUID = Pattern.compile(UIDRegex);
                Pattern patternPhone = Pattern.compile(phoneRegex);
                Pattern patternEmail = Pattern.compile(emailRegex);
                Matcher matcherUid = patternUID.matcher(resp_body_str);
                Matcher matcherPhone = patternPhone.matcher(resp_body_str);
                Matcher matcherEmail = patternEmail.matcher(resp_body_str);
                message = "SensitiveMessage:";
                if (matcherUid.find()){
                    message += ",UID";
                    payloads += "\n" + matcherUid.group();
                    while (matcherUid.find()){ //每次调用后会往后移
                        payloads += "\n" + matcherUid.group();
                    }
                }
                if (matcherPhone.find()){
                    message += ",Phone";
                    payloads += "\n" + matcherPhone.group();
                    while (matcherPhone.find()){ //每次调用后会往后移
                        payloads += "\n" + matcherPhone.group();
                    }
                }
                if (matcherEmail.find()){
                    message += ",Email";
                    payloads += "\n" + matcherEmail.group();
                    while (matcherEmail.find()){ //每次调用后会往后移
                        payloads += "\n" + matcherEmail.group();
                    }
                }
                if (!message.equalsIgnoreCase("SensitiveMessage:")) {
                    //不需要发包,上面正则匹配到则存在问题
                    logAdd(messageInfo, host, path, method, status, message, payloads);
                }
            }
        }
    }

}
