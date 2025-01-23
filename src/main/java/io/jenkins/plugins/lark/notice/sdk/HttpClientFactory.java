package io.jenkins.plugins.lark.notice.sdk;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.http.HttpClient;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Objects;

/**
 * A utility class for creating an HttpClient.
 * This factory can create clients that either validate SSL certificates or bypass them for testing purposes.
 *
 * @author xm.z
 */
public final class HttpClientFactory {

    private HttpClientFactory() {
        // Prevent instantiation of this utility class.
    }

    /**
     * Creates a new HttpClient instance configured to use the system's default SSL settings,
     * using the specified proxy settings. The client will perform standard SSL certificate validation.
     *
     * @param proxySelector The proxy selector to configure on the HttpClient, or null to use the default system proxy.
     * @return A new HttpClient instance configured with default SSL settings.
     */
    public static HttpClient buildHttpClient(ProxySelector proxySelector) {
        return buildHttpClient(proxySelector, false);
    }

    /**
     * Creates a new HttpClient instance. If bypassSslValidation is true, it will ignore SSL certificates.
     * This option should only be used in test environments and not in production.
     *
     * @param proxySelector       The proxy selector to configure on the HttpClient, or null to use the default system proxy.
     * @param bypassSslValidation True to bypass SSL certificate checks; false to use default SSL settings.
     * @return A new HttpClient instance configured according to the parameters.
     * @throws RuntimeException if there is an error during the creation of the HttpClient.
     */
    public static HttpClient buildHttpClient(ProxySelector proxySelector, boolean bypassSslValidation) {
        try {
            return HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .connectTimeout(Duration.ofSeconds(10))
                    .proxy(Objects.requireNonNullElse(proxySelector, ProxySelector.getDefault()))
                    .sslContext(createSSLContext(bypassSslValidation))
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create HttpClient", e);
        }
    }

    /**
     * Creates an SSL context based on whether SSL certificate validation should be bypassed.
     *
     * @param bypassSslValidation True to bypass SSL certificate checks; false to use default SSL settings.
     * @return An SSLContext instance configured according to the parameters.
     * @throws Exception if there is an error during the creation of the SSLContext.
     */
    private static SSLContext createSSLContext(boolean bypassSslValidation) throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        TrustManager[] trustManagers = bypassSslValidation ? new TrustManager[]{new BypassingTrustManager()} : null;
        sslContext.init(null, trustManagers, new SecureRandom());
        return sslContext;
    }

    /**
     * A trust manager that does not validate any certificates. Should only be used in test environments.
     */
    private static final class BypassingTrustManager extends X509ExtendedTrustManager {

        /**
         * {@inheritDoc}
         */
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
        }

    }
}