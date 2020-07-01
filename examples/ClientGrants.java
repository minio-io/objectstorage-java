package io.minio.http;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.introspect.VisibilityChecker;
import io.minio.MinioClient;
import io.minio.credentials.ClientGrantsCredentialsProvider;
import io.minio.credentials.CredentialsProvider;
import io.minio.messages.Bucket;
import io.minio.messages.ClientGrantsToken;
import java.beans.ConstructorProperties;
import java.io.IOException;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nonnull;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class ClientGrants {

  private static final String POLICY =
      new StringBuilder()
          .append("{\n")
          .append("    \"Statement\": [\n")
          .append("       " + " {\n")
          .append("            \"Action\": [\n")
          .append("                \"s3:GetBucketLocation\",\n")
          .append("                \"s3:ListBucket\"\n")
          .append("            ],\n")
          .append("            \"Effect\": \"Allow\",\n")
          .append("            \"Principal\": \"*\",\n")
          .append("            \"Resource\": \"arn:aws:s3:::test\"\n")
          .append("        }\n")
          .append("    ],\n")
          .append("    \"Version\": \"2012-10-17\"\n")
          .append("}\n")
          .toString();

  static class JwtToken {

    @JsonProperty("access_token")
    private final String accessToken;

    @JsonProperty("expires_in")
    private final long expiredAfter;

    @ConstructorProperties({"access_token", "expires_in"})
    public JwtToken(String accessToken, long expiredAfter) {
      this.accessToken = accessToken;
      this.expiredAfter = expiredAfter;
    }
  }

  @SuppressWarnings({"SameParameterValue", "squid:S1192"})
  static ClientGrantsToken getTokenAndExpiry(
      @Nonnull String clientId,
      @Nonnull String clientSecret,
      @Nonnull String idpClientId,
      @Nonnull String idpEndpoint) {
    Objects.requireNonNull(clientId, "Client id must not be null");
    Objects.requireNonNull(clientSecret, "ClientSecret must not be null");

    final RequestBody requestBody =
        new FormBody.Builder()
            .add("username", clientId)
            .add("password", clientSecret)
            .add("grant_type", "password")
            .add("client_id", idpClientId)
            .build();

    final Request request = new Request.Builder().url(idpEndpoint).post(requestBody).build();

    final OkHttpClient client = new OkHttpClient();
    try (Response response = client.newCall(request).execute()) {
      final ObjectMapper mapper = new ObjectMapper();
      mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
      mapper.setVisibility(
          VisibilityChecker.Std.defaultInstance()
              .withFieldVisibility(JsonAutoDetect.Visibility.ANY));

      final JwtToken jwtToken =
          mapper.readValue(Objects.requireNonNull(response.body()).charStream(), JwtToken.class);
      return new ClientGrantsToken(jwtToken.accessToken, jwtToken.expiredAfter, POLICY);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  @SuppressWarnings("squid:S106")
  public static void main(String[] args) throws Exception {
    final String clientId = "user";
    final String clientSecret = "password";
    final String idpEndpoint =
        "http://idp-host:idp-port/auth/realms/master/protocol/openid-connect/token";
    final String stsEndpoint = "http://sts-host:sts-port/sts";

    // client id for minio on idp
    final String idpClientId = "minio-client-id";

    final CredentialsProvider credentialsProvider =
        new ClientGrantsCredentialsProvider(
            stsEndpoint, () -> getTokenAndExpiry(clientId, clientSecret, idpClientId, idpEndpoint));

    final MinioClient minioClient =
        MinioClient.builder()
            .endpoint("http://minio-host:minio-port")
            .credentialsProvider(credentialsProvider)
            .build();

    final List<Bucket> buckets = minioClient.listBuckets();
    for (Bucket bucket : buckets) {
      System.out.print(bucket.name() + " created at ");
      System.out.println(bucket.creationDate());
    }
  }
}
