package api.gateway.utils;

import java.util.List;

public class Utils {
    public static boolean ifEmptyList(List<?> list) {
        return null == list || list.isEmpty();
    }

    public static boolean isEmptyString(String s) {
        return null == s || s.isEmpty() || s.isBlank();
    }
}
