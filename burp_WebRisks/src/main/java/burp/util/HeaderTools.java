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
        //websocket
        normalHeaderName.add("sec-websocket-key");
        normalHeaderName.add("sec-websocket-version");
        normalHeaderName.add("sec-websocket-accept");
        normalHeaderName.add("sec-websocket-protocol");
        normalHeaderName.add("sec-websocket-extensions");
        normalHeaderName.add("upgrade");

        return normalHeaderName.contains(headerName);
    }

    public static boolean isAuth(String headerName){
        List<String> authHeaderName = new ArrayList<>();
        authHeaderName.add("authorization");
        authHeaderName.add("cookie");

        return authHeaderName.contains(headerName);
    }

    public static boolean isWebsocket(String headerName){
        List<String> wssHeaderName = new ArrayList<>();
        wssHeaderName.add("sec-websocket-key");
        wssHeaderName.add("sec-webSocket-version");
        wssHeaderName.add("sec-webSocket-accept");
        wssHeaderName.add("sec-webSocket-protocol");
        wssHeaderName.add("sec-webSocket-extensions");
        wssHeaderName.add("upgrade");

        return wssHeaderName.contains(headerName);
    }
}
