package com.alumm0x.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class HeaderTools {

    // 静态字典
    //1.重点关注的响应数据类型
    public static List<String> ct = new ArrayList<>();
    static {
        ct.add("application/json");
        ct.add("application/xml");
        ct.add("text/xml");
        ct.add("application/xhtml+xml");
        ct.add("application/atom+xml");
        ct.add("application/octet-stream");
        ct.add("text/plain");
        ct.add("application/x-www-form-urlencoded ");
    }
    //2.常规的请求头部,保存标准规范的头部名称，用来过滤出自定义的头部
    public static List<String> rfc_reqheader = SourceLoader.loadSources("/rfc/rfc_reqheaders.bbm");
    
    //2.常规的响应头部,保存标准规范的头部名称，用来过滤出自定义的头部
    public static List<String> rfc_respheader = SourceLoader.loadSources("/rfc/rfc_respheaders.bbm");

    // 关于认证的请求头
    public static List<String> auth_header = SourceLoader.loadSources("/rfc/rfc_authheaders.bbm");

    // 关于websocket的请求头
    public static List<String> ws_reqheader = SourceLoader.loadSources("/rfc/rfc_wsheaders.bbm");

    // 关于cors的响应头
    public static List<String> cors_respheader = SourceLoader.loadSources("/rfc/rfc_corsheaders.bbm");


    public HeaderTools(){

    }

    //用于排除csrf的，记录常规的头部名称
    public static boolean inNormal(String headerName){
        return rfc_reqheader.contains(headerName.toLowerCase(Locale.ROOT));
    }

    //认证的请求头
    public static boolean isAuth(String headerName){
        return auth_header.contains(headerName.toLowerCase(Locale.ROOT));
    }

    //websocket的请求头
    public static boolean isWebsocket(String headerName){
        return ws_reqheader.contains(headerName.toLowerCase(Locale.ROOT));
    }

    //cors的响应头
    public static boolean isCors(String headerName){
        return cors_respheader.contains(headerName.toLowerCase(Locale.ROOT));
    }

    public static List<String> setXFF(){
        List<String> xffHeaderName = new ArrayList<>();
        xffHeaderName.add("X-Forwarded-For: 127.0.0.1");
        xffHeaderName.add("X-Originating-IP: 127.0.0.1");
        xffHeaderName.add("X-Remote-IP: 127.0.0.1");
        xffHeaderName.add("X-Remote-Addr: 127.0.0.1");

        return xffHeaderName;
    }
}
