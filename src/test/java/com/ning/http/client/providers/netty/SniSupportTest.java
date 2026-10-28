package com.ning.http.client.providers.netty;

import java.net.URI;
import java.util.Collections;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import org.testng.annotations.Test;
import static org.testng.Assert.*;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.AsyncHttpClientConfig;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.concurrent.*;
import javax.net.ssl.*;

public class SniSupportTest {
    @Test
    public void sendsSniInActualHttpsHandshake() throws Exception {
        KeyStore keys = KeyStore.getInstance("JKS");
        InputStream input = getClass().getClassLoader().getResourceAsStream("sni-test-keystore.jks");
        try { keys.load(input, "changeit".toCharArray()); } finally { input.close(); }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keys, "changeit".toCharArray());
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), null, null);
        final SSLServerSocket server = (SSLServerSocket) serverContext.getServerSocketFactory().createServerSocket(0);
        server.setSoTimeout(5000);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<String> received = executor.submit(new Callable<String>() {
            public String call() throws Exception {
                SSLSocket socket = (SSLSocket) server.accept();
                try {
                    socket.setSoTimeout(5000);
                    socket.startHandshake();
                    ExtendedSSLSession session = (ExtendedSSLSession) socket.getSession();
                    String name = ((SNIHostName) session.getRequestedServerNames().get(0)).getAsciiName();
                    socket.getInputStream().read();
                    socket.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".getBytes("US-ASCII"));
                    socket.getOutputStream().flush();
                    return name;
                } finally { socket.close(); }
            }
        });
        TrustManager[] trust = { new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) { }
            public void checkServerTrusted(X509Certificate[] c, String a) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext clientContext = SSLContext.getInstance("TLS");
        clientContext.init(null, trust, null);
        AsyncHttpClient client = new AsyncHttpClient(new AsyncHttpClientConfig.Builder().setSSLContext(clientContext)
                .setHostnameVerifier(new HostnameVerifier() { public boolean verify(String h, SSLSession s) { return true; } }).build());
        try {
            assertEquals(client.prepareGet("https://localhost:" + server.getLocalPort() + "/").execute().get(5, TimeUnit.SECONDS).getStatusCode(), 200);
            assertEquals(received.get(5, TimeUnit.SECONDS), "localhost");
        } finally { client.close(); server.close(); executor.shutdownNow(); }
    }
    @Test
    public void usesRequestHostnameAndPreservesExplicitConfiguration() throws Exception {
        SSLEngine engine = SSLContext.getDefault().createSSLEngine();
        engine.setUseClientMode(true);
        SniSupport.configure(engine, new URI("https://documents.example.com/documents"));
        assertEquals(engine.getSSLParameters().getServerNames(), Collections.singletonList(new SNIHostName("documents.example.com")));
        SniSupport.configure(engine, new URI("https://other.example.com/"));
        assertEquals(engine.getSSLParameters().getServerNames(), Collections.singletonList(new SNIHostName("documents.example.com")));
    }

    @Test
    public void ignoresIpLiterals() throws Exception {
        SSLEngine engine = SSLContext.getDefault().createSSLEngine();
        engine.setUseClientMode(true);
        SniSupport.configure(engine, new URI("https://127.0.0.1/"));
        assertNull(engine.getSSLParameters().getServerNames());
        SniSupport.configure(engine, new URI("https://[::1]/"));
        assertNull(engine.getSSLParameters().getServerNames());
    }
}
