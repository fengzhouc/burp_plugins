package burp.util;

import burp.IHttpRequestResponse;

public class CommonMess {
    /**
     * 用于存储公共数据的
     */
    // 保存当前需要认证才能访问的IHttpRequestResponse（IDOR任务中保存），用于检测登出后是否失效会话
    public static IHttpRequestResponse authMessageInfo = null;
    // SmsEmailBoom次数计数
    public static int SmsEmailBoomCount = 0;
}
