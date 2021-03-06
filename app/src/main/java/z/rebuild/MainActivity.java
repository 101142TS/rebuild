package z.rebuild;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import z.unpack.util.RootUtil;
import z.unpack.util.FileUtil;

import java.io.BufferedWriter;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.FileReader;
public class MainActivity extends AppCompatActivity {
    public final static String rebuildSo = "/data/local/tmp/librebuild.so";
    public final static String hookFile = "/data/local/tmp/unpack.txt";
    public final static String packageNameFile = "/data/local/tmp/mTargetPackage.txt";
    public final static int mWaitingTime = 5;
    public final static int mMode = 1;

    public MainActivity() {
        super();
    }

    public static String mTargetPackage = "";
    static {
        System.loadLibrary("rebuild");
    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = (TextView) findViewById(R.id.sample_text);
        tv.setText("rebuild");

        makeDirectoryAvaliable();
        moveSoFile();
        getmTargetPackage();
        savehookFile();
    }
    boolean moveSoFile() {
        File dataPath = new File(getFilesDir().getParentFile(), "lib");
        File soPath = new File(dataPath, "librebuild.so");
        File hookPath = new File(rebuildSo);
        if (soPath.lastModified() <= hookPath.lastModified()) {
            return true;
        }

        if (soPath.exists() && soPath.isFile()) {
            if (FileUtil.FileCopy(soPath.getAbsolutePath(), rebuildSo)) {
                RootUtil rootUtil = RootUtil.getInstance();
                if (rootUtil.startShell()) {
                    rootUtil.execute("chmod 777 " + rebuildSo, null);
                    Log.d("101142ts", "release target so file into " + rebuildSo);
                }
            } else {
                Log.e("101142ts", "release target so file failed");
            }
        }
        return true;
    }

    boolean makeDirectoryAvaliable() {
        File tmpFolder = new File("data/local/tmp");
        if (!tmpFolder.exists()) {
            tmpFolder.mkdirs();
        }
        if (!tmpFolder.canWrite() || !tmpFolder.canRead() || !tmpFolder.canExecute()) {
            RootUtil rootUtil = RootUtil.getInstance();
            if (rootUtil.startShell()) {
                rootUtil.execute("chmod 777 " + tmpFolder.getAbsolutePath(), null);
            }
        }
        return true;
    }

    boolean savehookFile() {
        File file = new File(hookFile);
        if (!file.exists()) {
            RootUtil rootUtil = RootUtil.getInstance();
            if (rootUtil.startShell()) {
                rootUtil.execute("touch " + hookFile, null);
                rootUtil.execute("chmod 777 " + hookFile, null);
            }
        }

        try {
            FileWriter writer = new FileWriter(file);
            BufferedWriter wr = new BufferedWriter(writer);
            wr.write(mTargetPackage + "\n");
            wr.write("rebuild" + "\n");
            wr.write(String.valueOf(mWaitingTime) + "\n");
            wr.write(String.valueOf(mMode) + "\n");
            wr.close();
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }
    boolean getmTargetPackage() {
        File file = new File(packageNameFile);
        if (!file.exists()) {
            return false;
        }
        try {
            FileReader reader = new FileReader(file);
            BufferedReader br = new BufferedReader(reader);
            mTargetPackage = br.readLine();

            br.close();
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        Log.e("101142ts", "mTargetPackage : " + mTargetPackage);
        return true;
    }
}
