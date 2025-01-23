/*
 * MinIO Java SDK for Amazon S3 Compatible Cloud Storage, (C) 2021 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.minio;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nonnull;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okio.BufferedSink;
import okio.Okio;

/** HTTP utilities. */
public class Http {
  public static final long DEFAULT_TIMEOUT = TimeUnit.MINUTES.toMillis(5);

  private static OkHttpClient enableJKSPKCS12Certificates(
      OkHttpClient httpClient,
      String trustStorePath,
      String trustStorePassword,
      String keyStorePath,
      String keyStorePassword,
      String keyStoreType)
      throws GeneralSecurityException, IOException {
    if (trustStorePath == null || trustStorePath.isEmpty()) {
      throw new IllegalArgumentException("trust store path must be provided");
    }
    if (trustStorePassword == null) {
      throw new IllegalArgumentException("trust store password must be provided");
    }
    if (keyStorePath == null || keyStorePath.isEmpty()) {
      throw new IllegalArgumentException("key store path must be provided");
    }
    if (keyStorePassword == null) {
      throw new IllegalArgumentException("key store password must be provided");
    }

    SSLContext sslContext = SSLContext.getInstance("TLS");
    KeyStore trustStore = KeyStore.getInstance("JKS");
    KeyStore keyStore = KeyStore.getInstance(keyStoreType);
    try (FileInputStream trustInput = new FileInputStream(trustStorePath);
        FileInputStream keyInput = new FileInputStream(keyStorePath); ) {
      trustStore.load(trustInput, trustStorePassword.toCharArray());
      keyStore.load(keyInput, keyStorePassword.toCharArray());
    }
    TrustManagerFactory trustManagerFactory =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(trustStore);

    KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());

    sslContext.init(
        keyManagerFactory.getKeyManagers(),
        trustManagerFactory.getTrustManagers(),
        new java.security.SecureRandom());

    return httpClient
        .newBuilder()
        .sslSocketFactory(
            sslContext.getSocketFactory(),
            (X509TrustManager) trustManagerFactory.getTrustManagers()[0])
        .build();
  }

  public static OkHttpClient enableJKSCertificates(
      OkHttpClient httpClient,
      String trustStorePath,
      String trustStorePassword,
      String keyStorePath,
      String keyStorePassword)
      throws GeneralSecurityException, IOException {
    return enableJKSPKCS12Certificates(
        httpClient, trustStorePath, trustStorePassword, keyStorePath, keyStorePassword, "JKS");
  }

  public static OkHttpClient enablePKCS12Certificates(
      OkHttpClient httpClient,
      String trustStorePath,
      String trustStorePassword,
      String keyStorePath,
      String keyStorePassword)
      throws GeneralSecurityException, IOException {
    return enableJKSPKCS12Certificates(
        httpClient, trustStorePath, trustStorePassword, keyStorePath, keyStorePassword, "PKCS12");
  }

  /**
   * copied logic from
   * https://github.com/square/okhttp/blob/master/samples/guide/src/main/java/okhttp3/recipes/CustomTrust.java
   */
  public static OkHttpClient enableExternalCertificates(OkHttpClient httpClient, String filename)
      throws GeneralSecurityException, IOException {
    Collection<? extends Certificate> certificates = null;
    try (FileInputStream fis = new FileInputStream(filename)) {
      certificates = CertificateFactory.getInstance("X.509").generateCertificates(fis);
    }

    if (certificates == null || certificates.isEmpty()) {
      throw new IllegalArgumentException("expected non-empty set of trusted certificates");
    }

    char[] password = "password".toCharArray(); // Any password will work.

    // Put the certificates a key store.
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    // By convention, 'null' creates an empty key store.
    keyStore.load(null, password);

    int index = 0;
    for (Certificate certificate : certificates) {
      String certificateAlias = Integer.toString(index++);
      keyStore.setCertificateEntry(certificateAlias, certificate);
    }

    // Use it to build an X509 trust manager.
    KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, password);
    TrustManagerFactory trustManagerFactory =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(keyStore);

    final KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
    final TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(keyManagers, trustManagers, null);
    SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

    return httpClient
        .newBuilder()
        .sslSocketFactory(sslSocketFactory, (X509TrustManager) trustManagers[0])
        .build();
  }

  public static OkHttpClient newDefaultClient() {
    OkHttpClient httpClient =
        new OkHttpClient()
            .newBuilder()
            .connectTimeout(DEFAULT_TIMEOUT, TimeUnit.MILLISECONDS)
            .writeTimeout(DEFAULT_TIMEOUT, TimeUnit.MILLISECONDS)
            .readTimeout(DEFAULT_TIMEOUT, TimeUnit.MILLISECONDS)
            .protocols(Arrays.asList(Protocol.HTTP_1_1))
            .build();
    String filename = System.getenv("SSL_CERT_FILE");
    if (filename != null && !filename.isEmpty()) {
      try {
        httpClient = enableExternalCertificates(httpClient, filename);
      } catch (GeneralSecurityException | IOException e) {
        throw new RuntimeException(e);
      }
    }
    return httpClient;
  }

  @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(
      value = "SIC",
      justification = "Should not be used in production anyways.")
  public static OkHttpClient disableCertCheck(OkHttpClient client)
      throws KeyManagementException, NoSuchAlgorithmException {
    final TrustManager[] trustAllCerts =
        new TrustManager[] {
          new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {}

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {}

            @Override
            public X509Certificate[] getAcceptedIssuers() {
              return new X509Certificate[] {};
            }
          }
        };

    final SSLContext sslContext = SSLContext.getInstance("SSL");
    sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
    final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

    return client
        .newBuilder()
        .sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0])
        .hostnameVerifier(
            new HostnameVerifier() {
              @Override
              public boolean verify(String hostname, SSLSession session) {
                return true;
              }
            })
        .build();
  }

  public static OkHttpClient setTimeout(
      OkHttpClient client, long connectTimeout, long writeTimeout, long readTimeout) {
    return client
        .newBuilder()
        .connectTimeout(connectTimeout, TimeUnit.MILLISECONDS)
        .writeTimeout(writeTimeout, TimeUnit.MILLISECONDS)
        .readTimeout(readTimeout, TimeUnit.MILLISECONDS)
        .build();
  }

  /** RequestBody that wraps a single data object. */
  public static class RequestBody extends okhttp3.RequestBody {
    private InputStream stream;
    private byte[] bytes;
    private long length;
    private MediaType contentType;

    private RequestBody(@Nonnull final MediaType contentType, final long length) {
      this.contentType = Utils.validateNotNull(contentType, "content type");
      if (length < 0) throw new IllegalArgumentException("length must not be negative value");
      this.length = length;
    }

    public RequestBody(
        @Nonnull final byte[] bytes, final int length, @Nonnull final MediaType contentType) {
      this(contentType, length);
      this.bytes = Utils.validateNotNull(bytes, "data bytes");
    }

    public RequestBody(
        @Nonnull final InputStream stream,
        final long length,
        @Nonnull final MediaType contentType) {
      this(contentType, length);
      this.stream = Utils.validateNotNull(stream, "stream");
    }

    @Override
    public MediaType contentType() {
      return contentType;
    }

    @Override
    public long contentLength() {
      return length;
    }

    @Override
    public void writeTo(BufferedSink sink) throws IOException {
      if (stream != null) {
        sink.write(Okio.source(stream), length);
      } else {
        sink.write(bytes, 0, (int) length);
      }
    }
  }

  /** HTTP methods. */
  public static enum Method {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE;
  }
}
