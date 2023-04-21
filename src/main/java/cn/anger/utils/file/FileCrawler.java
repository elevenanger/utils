package cn.anger.utils.file;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.RecursiveTask;

/**
 * @author : anger
 * 列举一个路径下所有的文件
 */
public class FileCrawler extends RecursiveTask<List<File>> {

    private final List<File> files = new ArrayList<>();
    private final File root;

    public FileCrawler(File root) {
        this.root = root;
    }

    @Override
    protected List<File> compute() {
        File [] files1 = root.listFiles();
        if (files1 == null)
            return Collections.emptyList();
        for (File file : files1) {
            if (file.isDirectory())
                files.addAll(new FileCrawler(file).compute());
            else
                files.add(file);
        }
        return files;
    }

    public List<File> getFiles() {
        return Collections.unmodifiableList(files);
    }

}
