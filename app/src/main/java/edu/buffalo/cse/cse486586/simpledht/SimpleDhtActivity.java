package edu.buffalo.cse.cse486586.simpledht;

import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.app.Activity;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

public class SimpleDhtActivity extends Activity {
    private Uri mUri = buildUri("content", "edu.buffalo.cse.cse486586.simpledht.provider");

    private Uri buildUri(String scheme, String authority) {
        Uri.Builder uriBuilder = new Uri.Builder();
        uriBuilder.authority(authority);
        uriBuilder.scheme(scheme);
        return uriBuilder.build();
    }
    private static String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
        //return String.valueOf(Math.abs(formatter.toString().hashCode())%128);
    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_simple_dht_main);
        
        final TextView tv = (TextView) findViewById(R.id.textView1);
        tv.setMovementMethod(new ScrollingMovementMethod());
        findViewById(R.id.button3).setOnClickListener(
                new OnTestClickListener(tv, getContentResolver()));
        Button lquery = (Button)findViewById(R.id.button1);
        lquery.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try{
                Cursor resultCursor = getContentResolver().query(mUri, null, "@", null,null);
                if (resultCursor.moveToFirst()) {
                    do {
                        String key = resultCursor.getString(resultCursor.getColumnIndex("key"));
                        String value = resultCursor.getString(resultCursor.getColumnIndex("value"));
                        String hash = genHash(key);
                        String data = "<" + key + ":" + value+">\n";//+":"+hash+"\n";
                        Log.e("DATA |||||||||||",  data );
                        tv.append(data);

                    } while (resultCursor.moveToNext());
                }
            }
                catch (Exception e)
                {
                    Log.e("OnClick", "onClick: Exception " );
                }
            }
        });

        Button delete = (Button) findViewById(R.id.Delete);
        delete.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                getContentResolver().delete(mUri,"@", null);
            }
        });
        Button gdump = (Button) findViewById(R.id.button2);
        gdump.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Cursor resultCursor  = getContentResolver().query(mUri, null, "*", null,null);
                if (resultCursor.moveToFirst()) {
                    do {
                        String key = resultCursor.getString(resultCursor.getColumnIndex("key"));
                        String value = resultCursor.getString(resultCursor.getColumnIndex("value"));
                        String data = "<" + key + ":" + value+">\n";//+":"+hash+"\n";
                        Log.e("Global DATA |||||||||||",  data );
                        tv.append(data);

                    } while (resultCursor.moveToNext());
                }
            }
        });

        Button GD = (Button) findViewById(R.id.button8);
        GD.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                getContentResolver().delete(mUri, "*", null);
            }
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.activity_simple_dht_main, menu);
        return true;
    }

}
