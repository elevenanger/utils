package cn.anger.utils.reflection;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;

/**
 * @author : anger
 * 反射相关的工具类
 */
public class ReflectionUtil {

    private ReflectionUtil() {}

    public static List<String> genericTypes(Field field) {
        String genericTypeInfo = field.getGenericType().getTypeName();
        genericTypeInfo = genericTypeInfo.replace(field.getType().getTypeName(), "");
        genericTypeInfo = genericTypeInfo.subSequence(1, genericTypeInfo.length() - 1).toString();
        return Arrays.asList(genericTypeInfo.split(","));
    }

}
