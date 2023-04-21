package cn.anger.utils.reflection;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

/**
 * @author : anger
 */
public class TypeToken<T> {
    private final Type type;
    protected TypeToken() {
        type = getParameterizedType(this.getClass());
    }

    private static Type getParameterizedType(Class<?> subClass) {
        Type superClass = subClass.getGenericSuperclass();
        if (superClass instanceof Class) {
            throw new IllegalStateException("没有类型参数");
        } else {
            ParameterizedType parameterizedType = (ParameterizedType) superClass;
            return parameterizedType.getActualTypeArguments()[0];
        }
    }

    public Type getType() {
        return type;
    }
}
