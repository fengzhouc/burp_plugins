package burp.util;

import java.util.ArrayList;
import java.util.List;

public class HeaderTools {

    public HeaderTools(){

    }

    //用于排除csrf的，记录常规的头部名称
    public static boolean inNormal(String headerName){
        List<String> normalHeaderName = new ArrayList<>();
        normalHeaderName.add("host");
        normalHeaderName.add("user-agent");
        normalHeaderName.add("accept");
        normalHeaderName.add("cookie");
        normalHeaderName.add("accept-language");
        normalHeaderName.add("accept-encoding");
        normalHeaderName.add("referer");
        normalHeaderName.add("origin");
        normalHeaderName.add("content-length");
        normalHeaderName.add("content-type");
        normalHeaderName.add("cache-control");
        normalHeaderName.add("pragma");
        normalHeaderName.add("connection");
        normalHeaderName.add("authorization"); //basic认证/bearer认证
        normalHeaderName.add("method");
        normalHeaderName.add("path");
        normalHeaderName.add("authority");
        normalHeaderName.add("schema");
        normalHeaderName.add("access-control-request-headers");
        normalHeaderName.add("access-control-request-method");
        normalHeaderName.add("access-control-allow-origin");
        normalHeaderName.add("access-control-allow-headers");
        normalHeaderName.add("access-control-allow-methods");
        normalHeaderName.add("access-control-allow-credentials");
        normalHeaderName.add("access-control-expose-headers");
        normalHeaderName.add("access-control-max-age");
        normalHeaderName.add("vary");
        normalHeaderName.add("date");
        normalHeaderName.add("x-http-method-override");
        normalHeaderName.add("x-requested-with");
        normalHeaderName.add("sec-fetch-dest");
        normalHeaderName.add("sec-fetch-mode");
        normalHeaderName.add("sec-fetch-site");
        //websocket
        normalHeaderName.add("sec-websocket-key");
        normalHeaderName.add("sec-websocket-version");
        normalHeaderName.add("sec-websocket-accept");
        normalHeaderName.add("sec-websocket-protocol");
        normalHeaderName.add("sec-websocket-extensions");
        normalHeaderName.add("upgrade");

        return normalHeaderName.contains(headerName);
    }

    //认证的请求头
    public static boolean isAuth(String headerName){
        List<String> authHeaderName = new ArrayList<>();
        authHeaderName.add("authorization");
        authHeaderName.add("cookie");

        return authHeaderName.contains(headerName);
    }

    //websocket的请求头
    public static boolean isWebsocket(String headerName){
        List<String> wssHeaderName = new ArrayList<>();
        wssHeaderName.add("sec-websocket-key");
        wssHeaderName.add("sec-websocket-version");
        wssHeaderName.add("sec-websocket-accept");
        wssHeaderName.add("sec-websocket-protocol");
        wssHeaderName.add("sec-websocket-extensions");
        wssHeaderName.add("upgrade");

        return wssHeaderName.contains(headerName);
    }

    //cors的响应头
    public static boolean isCors(String headerName){
        List<String> corsHeaderName = new ArrayList<>();
        corsHeaderName.add("access-control-allow-origin");
        corsHeaderName.add("access-control-allow-headers");
        corsHeaderName.add("access-control-allow-methods");
        corsHeaderName.add("access-control-allow-credentials");
        corsHeaderName.add("access-control-expose-headers");
        corsHeaderName.add("access-control-max-age");

        return corsHeaderName.contains(headerName);
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
