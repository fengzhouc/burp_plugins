package burp.util;

import java.util.ArrayList;
import java.util.List;

public class HeaderTools {

    public HeaderTools(){

    }

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

        return normalHeaderName.contains(headerName);
    }
}
