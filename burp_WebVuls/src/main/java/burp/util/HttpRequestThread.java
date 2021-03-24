package burp.util;

import burp.*;

public class HttpRequestThread implements Runnable {

    public String poc;
    public HttpResult resulemessageInfo = null;

    public HttpRequestThread(String poc){
        this.poc = poc;
    }

    @Override
    public void run() {
        //返回信息
        IHttpService iHttpService = BurpExtender.messageInfo.getHttpService();

        //返回上面板信息
        String url = BurpExtender.helpers.analyzeRequest(BurpExtender.messageInfo).getUrl().toString();

        //新的请求包
        byte[] req = buildMessage();
        IHttpRequestResponse messageInfo = BurpExtender.callbacks.makeHttpRequest(iHttpService, req);
        resulemessageInfo = new HttpResult(url, messageInfo);
    }

    public HttpResult getResulemessageInfo(){
        return resulemessageInfo;
    }

    // 指定位置填充poc
    private byte[] buildMessage(){
        byte[] editMessage = BurpExtender.editRequestViewer.getMessage();
        byte[] httpMessage = editMessage;
        String request = new String(editMessage);
        if (!request.equalsIgnoreCase("")){
            httpMessage = request.replace("$poc$", this.poc).getBytes();
        }
        return httpMessage;
    }
}
