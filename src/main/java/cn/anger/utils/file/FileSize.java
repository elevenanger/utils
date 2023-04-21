package cn.anger.utils.file;

import java.text.DecimalFormat;
import java.text.NumberFormat;

/**
 * @author : anger
 * 文件大小转换类
 */
public enum FileSize {

    BYTE(0, "B" ),
    KILO_BYTE(10, "KB"),
    MEGA_BYTE(20, "MB"),
    GIGA_BYTE(30, "GB"),
    TERA_BYTE(40, "TB");

    private final int shiftBit;
    private final String abbr;
    private final long unit;

    FileSize(int shiftBit, String abbr) {
        this.shiftBit = shiftBit;
        this.abbr = abbr;
        this.unit = 1L << shiftBit;
    }

    private static final NumberFormat formatter = new DecimalFormat("#.##");

    public double toSize(long byteSize) {
        return (double) byteSize / unit;
    }

    public double toSize(double size, FileSize target) {
        return size * unit / target.unit;
    }

    public static String toFixed(long byteSize) {
        if (byteSize < 0)
            throw new IllegalArgumentException("byte size must >= 0");

        FileSize fixedSize = FileSize.TERA_BYTE;

        for (int i = 1; i < values().length; i++) {
            if (byteSize >> values()[i].shiftBit == 0) {
                fixedSize = values()[i - 1];
                break;
            }
        }

        return formatter.format((double) byteSize / fixedSize.unit).concat(fixedSize.abbr);
    }

}
