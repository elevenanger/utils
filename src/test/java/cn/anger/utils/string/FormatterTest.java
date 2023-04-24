package cn.anger.utils.string;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * @author Anger
 * created on 2023/4/23
 */
class FormatterTest {

    final Map<String, String> kvMap = new HashMap<>();

    static final String WORD_PATTERN = "(\\w+)";

    static final String SEPARATOR = ";";

    static final String MAP_NOTATION = "=";

    static final String SRC = "a=1; b=2; c=3";

    static final String PATTERN =
            WORD_PATTERN
                .concat(MAP_NOTATION)
                .concat(WORD_PATTERN)
                .concat(SEPARATOR)
                .concat("?");

    @Test
    void test() {

        System.out.println("src str => " + SRC);

        Pattern p = Pattern.compile(PATTERN);
        Matcher m = p.matcher(SRC);

        while (m.find())
            kvMap.put(m.group(1), m.group(2));

        kvMap.put("d", "4");
        kvMap.put("e", "5");

        String gen = kvMap.entrySet().stream()
                .map(entry -> entry.getKey().concat(MAP_NOTATION).concat(entry.getValue()))
                .collect(Collectors.joining(SEPARATOR));

        System.out.println("generated str => " + gen);
    }

}