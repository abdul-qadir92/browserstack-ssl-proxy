package com.example.sslproxy;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class MainActivity extends AppCompatActivity {
    String proxyHost, host;
    int proxyPort, port;
    SSLSocket socket;
    SSLSocketFactory factory;
    @Override
    protected void onCreate(Bundle savedInstanceState){
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        EditText ipAddressInput = findViewById(R.id.ipaddress);
        EditText portInput = findViewById(R.id.port);
        Button connectButton = findViewById(R.id.connect);
        connectButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                host = ipAddressInput.getText().toString();
                port = Integer.parseInt(portInput.getText().toString());
                try{
                    proxyHost = System.getProperty("https.proxyHost");
                    proxyPort = Integer.parseInt(System.getProperty("https.proxyPort"));
                    System.out.println("Proxy Detected: "+proxyHost+" : "+proxyPort);
                    SSLSocketClientWithTunneling(host,port,true);
                }catch(Exception e){
                    System.out.println("No Proxy Detected");
                    try {
                        SSLSocketClientWithTunneling(host,port,false);
                    } catch (IOException ioException) {
                        ioException.printStackTrace();
                    }
                }
            }
        });
    }

    private void SSLSocketClientWithTunneling(String host, int port, boolean tunnel) throws IOException  {
        new Thread(new Runnable() {
            @Override
            public void run() {
                factory  = (SSLSocketFactory)SSLSocketFactory.getDefault();
                Socket proxySocket = null;
                if(tunnel){
                    try {
                        proxySocket = new Socket(proxyHost, proxyPort);
                        System.out.println("Proxy Socket Created");
                        doTunnelHandshake(proxySocket, host, port);
                        System.out.println("Proxy Socket Connected:"+ host);
                        socket = (SSLSocket)factory.createSocket(proxySocket, host, port, false);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }else{
                    try {
                        socket = (SSLSocket)factory.createSocket(host, port);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

                try {
                    socket.addHandshakeCompletedListener(
                            new HandshakeCompletedListener() {
                                public void handshakeCompleted(HandshakeCompletedEvent event) {
                                    System.out.println("Handshake finished!");
                                    System.out.println(
                                            "\t PeerHost " + event.getSession().getPeerHost());
                                    System.out.println(
                                            "\t CipherSuite:" + event.getCipherSuite());
                                    System.out.println(
                                            "\t SessionId " + event.getSession());
                                    System.out.println(
                                            "\t Protocol Version " + event.getSession().getProtocol());
                                }
                            }
                    );
                    /*
                     * send http request
                     *
                     * Before any application data is sent or received, the
                     * SSL socket will do SSL handshaking first to set up
                     * the security attributes.
                     *
                     * SSL handshaking can be initiated by either flushing data
                     * down the pipe, or by starting the handshaking by hand.
                     *
                     * Handshaking is started manually in this example because
                     * PrintWriter catches all IOExceptions (including
                     * SSLExceptions), sets an internal error flag, and then
                     * returns without rethrowing the exception.
                     *
                     * Unfortunately, this means any error messages are lost,
                     * which caused lots of confusion for others using this
                     * code.  The only way to tell there was an error is to call
                     * PrintWriter.checkError().
                     */
                    socket.startHandshake();
                    PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));

                    out.println("GET / HTTP/1.1");
                    out.println();
                    out.flush();

                    if (out.checkError())
                        System.out.println(
                                "SSLSocketClient:  java.io.PrintWriter error");

                    /* read response */
                    BufferedReader in = new BufferedReader(
                            new InputStreamReader(
                                    socket.getInputStream()));

                    String inputLine;
                    int line=1;
                    while ((inputLine = in.readLine()) != null && line<3)  {
                        System.out.println(inputLine);
                        line += line;
                    }

                    in.close();
                    out.close();
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }).start();

    }

    private void doTunnelHandshake(Socket proxySocket, String host, int port) throws IOException {
        OutputStream out = proxySocket.getOutputStream();
        String msg = "CONNECT " + host + ":" + port + " HTTP/1.1\n\n";
        byte b[];
        try {
            b = msg.getBytes("ASCII7");
        } catch (UnsupportedEncodingException ignored) {
            b = msg.getBytes();
        }
        out.write(b);
        out.flush();

        byte            reply[] = new byte[200];
        int             replyLen = 0;
        int             newlinesSeen = 0;
        boolean         headerDone = false;     /* Done on first newline */

        InputStream in = proxySocket.getInputStream();
        boolean         error = false;

        while (newlinesSeen < 2) {
            int i = in.read();
            if (i < 0) {
                throw new IOException("Unexpected EOF from proxy");
            }
            if (i == '\n') {
                headerDone = true;
                ++newlinesSeen;
            } else if (i != '\r') {
                newlinesSeen = 0;
                if (!headerDone && replyLen < reply.length) {
                    reply[replyLen++] = (byte) i;
                }
            }
        }
        String replyStr;
        try {
            replyStr = new String(reply, 0, replyLen, "ASCII7");
        } catch (UnsupportedEncodingException ignored) {
            replyStr = new String(reply, 0, replyLen);
        }

        /* We asked for HTTP/1.1, so we should get that back */
        if (!replyStr.startsWith("HTTP/1.1 200")) {
            throw new IOException("Unable to tunnel through "
                    + proxyHost + ":" + proxyPort
                    + ".  Proxy returns \"" + replyStr + "\"");
        }
    }

}

