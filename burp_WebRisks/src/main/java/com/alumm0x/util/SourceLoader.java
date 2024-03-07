package com.alumm0x.util;

import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class SourceLoader {

    /**
     * 从classpath下获取文件内容
     * @param filepath 文件路径，相对classpath根目录，如根目录直接文件名即可，如果/api/test.txt则api/test.txt
     * @return List
     */
    public static List<String> loadSources(String filepath){
        List<String> payloads = new ArrayList<>();
        InputStream inStream = SourceLoader.class.getResourceAsStream(filepath);
        assert inStream != null;
        try(Scanner scanner = new Scanner(inStream)){
            while (scanner.hasNextLine()){
                String line = scanner.nextLine();
                // 排除掉#开头的注释
                if (!line.startsWith("#")) {
                    payloads.add(line.trim());
                }
            }
        }
        return payloads;
    }


    /**
     * 获取resource下的文件，返回其URL对象
     * @param filepath 文件名，相对classpath根目录，如根目录直接文件名即可，如果/api/test.txt则api/test.txt
     * @return URL
     */
    public static URL loadSourceToUrl(String filepath){
        return SourceLoader.class.getClassLoader().getResource(filepath);
    }
}
