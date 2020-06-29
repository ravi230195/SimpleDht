package edu.buffalo.cse.cse486586.simpledht;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Formatter;
import java.util.HashSet;
import java.util.Iterator;
import java.util.SortedMap;
import java.util.TreeMap;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

public class SimpleDhtProvider extends ContentProvider {

    private static String TAG = SimpleDhtProvider.class.getName();
    private static int myPort;
    private static String myHash;
    private static int SERVER_PORT = 10000;
    private static int successor;
    private static int predecessor = -1;
    private static HashSet<String> myData = new HashSet();
    private static SortedMap<String, Integer> ring = new TreeMap<String, Integer>();
    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        Log.e(TAG, "delete: METHOND CALLED " + selection );
        if (selection.equals("@")){
            Iterator<String> it = myData.iterator();
            while (it.hasNext()) {
                String key = it.next();
                it.remove();
                getContext().deleteFile(key);
                Log.e(TAG, "delete: Removed " + key);
            }
        }
        else if (selection.equals("*"))
        {
            Iterator<String> it = myData.iterator();
            while (it.hasNext()) {
                String key = it.next();
                it.remove();
                getContext().deleteFile(key);
                Log.e(TAG, "delete: Removed " + key);
            }

            try {
                String successorTemp = String.valueOf(successor);
                String msg = "DELETE";
                while (!successorTemp.equals(String.valueOf(myPort))) {
                    String data = new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, successorTemp).get();
                    String[] receivedData = data.split("!");
                    Log.e(TAG, "Delted: Data From " + successorTemp + String.format(" Data[%s]", receivedData[0]));
                    successorTemp = receivedData[1];
                }
            }
            catch (Exception e)
            {
                Log.e(TAG, "delete: Exception " + e.getMessage() + e.getClass());
            }
        }
        else
        {
            if (myData.contains(selection))
            {
                myData.remove(selection);
                getContext().deleteFile(selection);
                Log.e(TAG, "delete: Removed " + selection);

            }
        }
        return 0;
    }

    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // TODO Auto-generated method stub
        try
        {
            String keyValue = values.getAsString("key");
            String val = values.getAsString("value");
            String hashKey = genHash(keyValue);
            String predecessorHash = genHash(String.valueOf(predecessor/2));
            Log.e(TAG, String.format("insert: key:[%s] value:[%s] hash:[%s] predecessor:[%d] predecessorHash:[%s], myHash:[%s]", keyValue, val, hashKey, predecessor, predecessorHash, myHash));
            boolean condition_1 = (myHash.compareTo(predecessorHash) > 0) && (hashKey.compareTo(predecessorHash) >= 0) && (hashKey.compareTo(myHash) < 0);
            boolean condition_2 = (myHash.compareTo(predecessorHash) < 0) && (hashKey.compareTo(predecessorHash) >= 0 || hashKey.compareTo("0000000000000000000000000000000000000000") >= 0 && hashKey.compareTo(myHash) < 0);
            String condition_1val = condition_1 ? "True":"False";
            String condition_2val = condition_2 ? "True":"False";
            Log.e(TAG, String.format("insert: con1[%s] and con2[%s]", condition_1val, condition_2val));
            if ( condition_1 || condition_2 || predecessor == -1) {
                Log.e(TAG, "insert: ||||||||||||||| Instering Data....");
                myData.add(keyValue);
                FileOutputStream output = getContext().openFileOutput(keyValue, Context.MODE_PRIVATE);
                output.write(val.getBytes());
                output.flush();
                output.close();
            }
            else
            {
                Log.e(TAG, "insert: Sending data to " + successor );
                String msg = "INSERT";
                msg = msg + ":" + keyValue + ":" + val;
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, String.valueOf(successor));
            }
        }
        catch (Exception e)
        {
            Log.e(TAG, "insert: Error Inserting " + e.getCause());
        }
        Log.v("insert", values.toString());
        return uri;
    }

    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub
        try {
            TelephonyManager tel = (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
            String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
            myPort = (Integer.parseInt(portStr) * 2);
            myHash = genHash(Integer.toString(myPort/2));
            Log.e(TAG, String.format("onCreate: AVD port [%s] and HashValue [%s]", myPort, myHash));
            Log.e(TAG, "onCreate: Creating Server");
            successor = myPort;
            ServerSocket serverSocket = new ServerSocket(); // <-- create an unbound socket first
            serverSocket.bind(new InetSocketAddress(SERVER_PORT));
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);

            if (myPort == 11108)
            {
                successor = 11108;
                //predecessor = -1;
                ring.put(myHash, myPort);
            }
            else
            {
                String msg = "JOIN:" + myPort;

                String ports = new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, "11108").get();
                if (ports != null) {
                    String[] port = ports.split(":");
                    successor = Integer.parseInt(port[0]);
                    predecessor = Integer.parseInt(port[1]);
                    Log.e(TAG, String.format("onCreate: my Successor [%s] and predecessor [%s]", successor, predecessor));
                    String updateSuccessor = "UPDATE_SUCCESSOR:" + myPort;
                    String updatePredecessor = "UPDATE_PREDECESSOR:" + myPort;
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, updatePredecessor, Integer.toString(successor)).get();
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, updateSuccessor, Integer.toString(predecessor));
                    msg = "TRANSFER_DATA";
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, String.valueOf(successor));
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, "11108");
                }
            }
            Log.e(TAG, String.format("onCreate: successor [%s] and predecessor [%s]", successor, predecessor));
        }
        catch (Exception e)
        {
            Log.e(TAG, "onCreate: Exception " + e.getMessage() + " " +e.getClass());
            return false;
        }
        return false;
    }

    public Cursor convertToMatrix(String data)
    {
        String[] keyValurPairs = data.split("#");
        MatrixCursor cursor = new MatrixCursor(new String[]{"key", "value"});
        for (int i = 0; i < keyValurPairs.length; i++)
        {
            String[] pair = keyValurPairs[i].split(":");
            MatrixCursor.RowBuilder table = cursor.newRow();
            table.add("key", pair[0]);
            table.add("value", pair[1]);
        }
        return cursor;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
            String sortOrder) {
        // TODO Auto-generated method stub
        try {
            if (selection.equals("@")) {
                Iterator<String> it = myData.iterator();
                MatrixCursor cursor = new MatrixCursor(new String[]{"key", "value"});
                while (it.hasNext()) {
                    String key = it.next();
                    Log.e(TAG, "Serch FileSystem for : |||||||||  " + key);
                    FileInputStream input = getContext().openFileInput(key);

                    byte[] buffer = new byte[(int) input.getChannel().size()];
                    input.read(buffer);
                    String value = "";
                    for (byte b : buffer) value += (char) b;
                    input.close();
                    MatrixCursor.RowBuilder table = cursor.newRow();
                    table.add("key", key);
                    table.add("value", value);
                }
                Log.e(TAG, "query: Number or Rows" + cursor.getCount() );
                return cursor;
            }
            else if(selection.equals("*"))
            {
                String msg = "QUERY:@";
                String globaldata = "";

                Iterator<String> it = myData.iterator();
                while (it.hasNext()) {
                    String key = it.next();
                    Log.e(TAG, "Serch FileSystem for: ||||||||| " + key);
                    FileInputStream input = getContext().openFileInput(key);

                    byte[] buffer = new byte[(int) input.getChannel().size()];
                    input.read(buffer);
                    String value = "";
                    for (byte b : buffer) value += (char) b;
                    String keyValue = key + ":" + value + "#";
                    globaldata = globaldata + keyValue;
                }

                String successorTemp = String.valueOf(successor);
                while(!successorTemp.equals(String.valueOf(myPort)))
                {
                    String data = new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, successorTemp).get();
                    String [] receivedData = data.split("!");
                    Log.e(TAG, "query: Data From " + successorTemp + String.format(" Data[%s]", receivedData[0]));
                    successorTemp = receivedData[1];

                    if (!receivedData[0].isEmpty())
                        globaldata = globaldata + receivedData[0] + "#";
                }
                if (!globaldata.isEmpty())
                    globaldata = globaldata.substring(0, globaldata.length() - 1);
                Log.e(TAG, "query: Received globalData" + globaldata );
                return convertToMatrix(globaldata);
            }
            else
            {
                if (myData.contains(selection)) {
                    FileInputStream input = getContext().openFileInput(selection);

                    byte[] buffer = new byte[(int) input.getChannel().size()];
                    input.read(buffer);
                    String value = "";
                    for (byte b : buffer) value += (char) b;
                    input.close();
                    //Log.v("query value ",   Integer.toString(numberOfBytes));
                    MatrixCursor cursor = new MatrixCursor(new String[]{"key", "value"});
                    MatrixCursor.RowBuilder table = cursor.newRow();
                    table.add("key", selection);
                    table.add("value", value);
                    return cursor;
                }
                else
                {
                    String msg = "QUERY:" + selection;
                    String value = new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, String.valueOf(successor)).get();
                    value = value.split(":")[1];
                    MatrixCursor cursor = new MatrixCursor(new String[]{"key", "value"});
                    MatrixCursor.RowBuilder table = cursor.newRow();
                    table.add("key", selection);
                    table.add("value", value);
                    Log.e(TAG, String.format("query: Query Retured fro key[%s] value[%s]", selection, value));
                    return cursor;
                }
            }
        }
        catch (Exception e)
        {
            Log.e(TAG, "query: Query Exception" +e.getMessage() );
        }
        return null;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
        //return String.valueOf(Math.abs(formatter.toString().hashCode())%128);
    }



    class ServerTask extends AsyncTask<ServerSocket, Void, Void>
    {
        private Uri mUri = buildUri("content", "edu.buffalo.cse.cse486586.simpledht.provider");

        private Uri buildUri(String scheme, String authority) {
            Uri.Builder uriBuilder = new Uri.Builder();
            uriBuilder.authority(authority);
            uriBuilder.scheme(scheme);
            return uriBuilder.build();
        }

        String handleMessage(String recv) {
            try {
                String[] extract = recv.split(":");
                String msg = extract[0];
                if (msg.equals("JOIN")) {
                    if (myPort != 11108) {
                        Log.e(TAG, "handleMessage: Something WRONG JOIN sent Wrong");

                    } else {

                        int desPort =  Integer.parseInt(extract[1]);
                        ring.put(genHash(String.valueOf(desPort/2)), desPort);
                        ArrayList<String> rigListHash = new ArrayList<String>(ring.keySet());
                        ArrayList<Integer> rigListPort = new ArrayList<Integer>(ring.values());
                        int i = rigListPort.indexOf(Integer.parseInt(extract[1]));
                        Log.e(TAG, "handleMessage: Index " + i);
                        Log.e(TAG, "handleMessage: ring port " + Arrays.toString(rigListPort.toArray()));
                        int succ = 0;
                        int pred = 0;
                        if (i+1 >= rigListHash.size())
                            succ = rigListPort.get(0);
                        else
                            succ = rigListPort.get(i+1);
                        if (i <= 0)
                            pred = rigListPort.get(rigListPort.size()-1);
                        else
                            pred = rigListPort.get(i-1);
                        Log.e(TAG, String.format("handleMessage: succ:[%s] and pred:[%s]", succ, pred));
                        String result = String.valueOf(succ) + ":" + String.valueOf(pred);
                        return result;
                    }
                } else if (msg.equals("INSERT")) {
                     String key = extract[1];
                     String value = extract[2];
                     ContentValues contentValues = new ContentValues();
                     contentValues.put("key", key);
                     contentValues.put("value", value);
                     insert(mUri, contentValues);
                     return "ACK";

                } else if (msg.equals("QUERY")) {
                    String selection = extract[1];
                    Cursor resultCursor = query(mUri, null, selection, null,null);
                    String data = "";
                    if (resultCursor.moveToFirst()) {
                        do {
                            String key = resultCursor.getString(resultCursor.getColumnIndex("key"));
                            String value = resultCursor.getString(resultCursor.getColumnIndex("value"));
                            String hash = genHash(key);
                            data = data + key + ":" + value + "#";//+":"+hash+"\n";
                            Log.e("DATA |||||||||||",  data );
                        } while (resultCursor.moveToNext());
                    }
                    if (!data.isEmpty())
                        data = data.substring(0, data.length() - 1);
                    if(selection.equals("@"))
                        data = data + "!" + successor;
                    Log.e("Global DATA |||||||||||",  data );
                    return data;

                } else if (msg.equals("TRANSFER_DATA")) {
                    Iterator<String> it = myData.iterator();
                    //ArrayList<ContentValues> contentValues =  new ArrayList<ContentValues>();
                    while (it.hasNext())
                    {
                        String key = it.next();
                        String hashKey = genHash(key);
                        String predecessorHash = genHash(String.valueOf(predecessor/2));
                        Log.e(TAG, String.format("TRANSFER: key:[%s] hash:[%s] predecessor:[%d] predecessorHash:[%s], myHash:[%s]", key, hashKey, predecessor, predecessorHash, myHash));
                        boolean condition_1 = (myHash.compareTo(predecessorHash) > 0) && (hashKey.compareTo(predecessorHash) >= 0) && (hashKey.compareTo(myHash) < 0);
                        boolean condition_2 = (myHash.compareTo(predecessorHash) < 0) && (hashKey.compareTo(predecessorHash) >= 0 || hashKey.compareTo("0000000000000000000000000000000000000000") >= 0 && hashKey.compareTo(myHash) < 0);
                        String condition_1val = condition_1 ? "True":"False";
                        String condition_2val = condition_2 ? "True":"False";
                        Log.e(TAG, String.format("Transfer: con1[%s] and con2[%s]", condition_1val, condition_2val));
                        if ( condition_1 || condition_2) {
                            continue;
                        }
                        else
                        {
                            Cursor resultCursor = query(mUri, null, key, null, null);
                            int keyIndex = resultCursor.getColumnIndex("key");
                            int valueIndex = resultCursor.getColumnIndex("value");
                            resultCursor.moveToFirst();

                            String returnKey = resultCursor.getString(keyIndex);
                            String returnValue = resultCursor.getString(valueIndex);
                            resultCursor.close();
                            it.remove();
                            getContext().deleteFile(key);
                            String msgInsert = "INSERT:" + key + ":" + returnValue;
                            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msgInsert, String.valueOf(predecessor));
                        }
                    }
                    return "ACK";
                }
                else  if(msg.equals("UPDATE_SUCCESSOR"))
                {
                    successor = Integer.parseInt(extract[1]);
                    return "ACK";
                }
                else if(msg.equals("UPDATE_PREDECESSOR"))
                {
                    predecessor = Integer.parseInt(extract[1]);
                    return "ACK";
                }
                else if (msg.equals("DELETE"))
                {
                    delete(mUri, "@", null);
                    return "ACK!" + successor;
                }
                else {
                    Log.e(TAG, "handleMessage: ||||||||||||||| Something Went Wrong ");
                }
            }
            catch (Exception e)
            {
                Log.e(TAG, "handleMessage: Exception" +e.getClass() + e.getMessage());
            }
            return "ACK";

        }


        @Override
        protected Void doInBackground(ServerSocket... serverSockets) {
            try {
                ServerSocket serverSocket = serverSockets[0];
                while(true)
                {
                    Log.e(TAG, "Server Waiting for Connection" );
                    try {
                        Socket socket = serverSocket.accept();
                        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                        String msg = in.readLine();
                        Log.e(TAG, "MESSAGE RECEIVED : " + msg );
                        String response = handleMessage(msg) + "\n";
                        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
                        out.write(response);
                        out.flush();

                    }
                    catch (Exception e)
                    {
                        Log.e(TAG, "doInBackground:SERVER After accept Exceptio" + e.getClass() + " " + e.getMessage() );
                    }

                }
            }catch (Exception e)
            {
                Log.e(TAG, "doInBackground:SERVER Exception" + e.getClass() + " " + e.getMessage() );
            }
            return null;
        }
    }

    class ClientTask extends AsyncTask<String, Void , String>
    {
        @Override
        protected String doInBackground(String... params) {
            String msg = params[0] + "\n";
            String sendingPort = params[1];
            String recv = null;
            try {
                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(sendingPort));
                BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
                out.write(msg);
                out.flush();

                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String ACK = "ACK";
                recv = in.readLine();
                if (recv.equals(ACK) || !recv.isEmpty()) {
                    out.close();
                    in.close();
                    socket.close();
                }
            } catch (SocketTimeoutException e) {

                Log.e(TAG, "doInBackground:Client UnknownHostException" + e.getMessage());
            } catch (UnknownHostException e) {

                Log.e(TAG, "doInBackground:Client UnknownHostException" + e.getMessage());
            } catch (IOException e) {

                Log.e(TAG, "doInBackground:Client socket IOException" + e.getMessage());
            } catch (Exception e) {

                Log.e(TAG, "doInBackground:Client socket Exception" + e.getMessage());
            }
            finally {
                return recv;
            }
        }
    }


}
