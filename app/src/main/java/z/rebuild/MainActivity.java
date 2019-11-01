package z.rebuild;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import z.unpack.util.RootUtil;
import z.unpack.util.FileUtil;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

public class MainActivity extends AppCompatActivity {
    public final static String rebuildSo = "/data/local/tmp/librebuild.so";
    public final static String hookFile = "/data/local/tmp/unpack.txt";
    public final static int mWaitingTime = 5;
    public final static int mMode = 1;

    public MainActivity() {
        super();
    }

    //public final static String mTargetPackage = "com.vjson.animde";  //legu 2.10.2.2
    //public final static String mTargetPackage = "com.jr.kingofglorysupport"; //legu 2.10.2.3
    //public final static String mTargetPackage = "com.billy.sdclean"; //2.10.4.0
    //public final static String mTargetPackage = "org.fuyou.wly";    //libjiagu.so 12e8d2721ae9109b1332540311376344
    //public final static String mTargetPackage = "com.example.eisk.cn";    //libjiagu.so b6dd50c44eead298423d1853025cfe17
    //public final static String mTargetPackage = "com.systoon.beijingtoon";  //libjiagu.so   91d2e05ac30d91afbf02a8e2d4448d14
    //public final static String mTargetPackage = "com.majun.landlordtreasure";   //libjiagu.so   c777cc1017287f00d9cdd022b867d8ae
    //public final static String mTargetPackage = "cbp.game.chess"; //libjiagu.so    f880afeacaf320cd2eaf44a928aa9d91
    //public final static String mTargetPackage = "com.nanxi.a411"; //libjiagu.so b080d680f71862a4d7b4ccf9e41853e5
    //public final static String mTargetPackage = "com.huxiu";    //liabjiagu.so bdc6e7786076696da260d8bbbafe570e
    //public final static String mTargetPackage = "com.huxiu";    //liabjiagu.so f0fa7384273217a2431ab1c60ed21037
    //public final static String mTargetPackage = "com.huxiu";    //liabjiagu.so efe21d36f54114e1067b620071573265
    //public final static String mTargetPackage = "com.mytest.demo"; //Bangle Demo
    //public final static String mTargetPackage = "com.pmp.ppmoney";
    //public final static String mTargetPackage = "zzz.jjni"; //360sample
    //public final static String mTargetPackage = "com.sf.activity";   //assets/ijm_lib/   20190412
    //public final static String mTargetPackage = "com.yanxin.eloanan";   //assets/main000/   20190321
    //public final static String mTargetPackage = "com.sf.activity";   //assets/ijm_lib/
    //public final static String mTargetPackage = "com.iss.qilubank";
    //public final static String mTargetPackage = "com.greenpoint.android.mc10086.activity";
    //public final static String mTargetPackage = "com.icbc";
    //public final static String mTargetPackage = "com.perflyst.twire";
    //public final static String mTargetPackage = "com.example.simple";
    //public final static String mTargetPackage = "com.xargsgrep.portknocker";
    //public final static String mTargetPackage = "org.scoutant.blokish";
    //public final static String mTargetPackage = "org.zirco";
    //public final static String mTargetPackage = "edu.testapk.crackme";
    //public final static String mTargetPackage = "github.vatsal.easyweatherdemo";
    //public final static String mTargetPackage = "com.xargsgrep.portknocker";
    //public final static String mTargetPackage = "org.csploit.android";
    //public final static String mTargetPackage = "jp.forkhub";
    //public final static String mTargetPackage = "io.github.hopedia";
    //public final static String mTargetPackage = "org.schabi.newpipelegacy";
    //public final static String mTargetPackage = "eu.depau.etchdroid";
    public final static String mTargetPackage = "com.qihoo360.mobilesafe.opti.powerctl";
    //public final static String mTargetPackage = "com.forever.browser";
    //public final static String mTargetPackage = "com.softbank.mbank.xy.qhjd";
    //public final static String mTargetPackage = "com.picc.aasipods";
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
}
