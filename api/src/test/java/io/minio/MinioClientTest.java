/*
 * MinIO Java SDK for Amazon S3 Compatible Cloud Storage,
 * (C) 2015, 2016, 2017 MinIO, Inc.
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

import static org.junit.Assert.assertEquals;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import io.minio.errors.ErrorResponseException;
import io.minio.errors.InvalidEndpointException;
import io.minio.errors.InvalidExpiresRangeException;
import io.minio.errors.InvalidResponseException;
import io.minio.errors.MinioException;
import io.minio.errors.RegionConflictException;
import io.minio.messages.Bucket;
import io.minio.messages.ErrorResponse;
import io.minio.messages.Item;
import io.minio.messages.Owner;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Iterator;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okio.Buffer;
import org.junit.Assert;
import org.junit.Test;
import org.xmlpull.v1.XmlPullParserException;

@SuppressWarnings("unused")
public class MinioClientTest {
  private static final String EXPECTED_EXCEPTION_DID_NOT_FIRE = "Expected exception did not fire";
  private static final String BUCKET = "bucket";
  private static final String CONTENT_LENGTH = "Content-Length";
  private static final String APPLICATION_OCTET_STREAM = "application/octet-stream";
  private static final String APPLICATION_JAVASCRIPT = "application/javascript";
  private static final String CONTENT_TYPE = "Content-Type";
  private static final String MON_04_MAY_2015_07_58_51_GMT = "Mon, 04 May 2015 07:58:51 GMT";
  private static final String LAST_MODIFIED = "Last-Modified";
  private static final String HELLO_WORLD = "hello world";
  private static final String HELLO = "hello";
  private static final String BYTES = "bytes";
  private static final String ENC_KEY = "x-amz-meta-x-amz-key";
  private static final String ENC_IV = "x-amz-meta-x-amz-iv";
  private static final String MAT_DESC = "x-amz-meta-x-amz-matdesc";
  private static final String ACCEPT_RANGES = "Accept-Ranges";
  private static final String CONTENT_RANGE = "Content-Range";
  private static final String MON_29_JUN_2015_22_01_10_GMT = "Mon, 29 Jun 2015 22:01:10 GMT";
  private static final String BUCKET_KEY = "/bucket/key";
  private static final String MD5_HASH_STRING = "\"5eb63bbbe01eeed093cb22bb8f5acdc3\"";
  private static final ObjectMapper objectMapper =
      new ObjectMapper().enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY);

  @Test()
  public void setUserAgentOnceSet() throws IOException, MinioException {
    String expectedHost = "example.com";
    MinioClient client = new MinioClient("http://" + expectedHost + "/");
    client.setAppInfo("testApp", "3.0.0");
  }

  @Test(expected = MinioException.class)
  public void newClientWithPathFails() throws MinioException {
    new MinioClient("http://example.com/path");
    throw new RuntimeException(EXPECTED_EXCEPTION_DID_NOT_FIRE);
  }

  @SuppressFBWarnings("NP")
  @Test(expected = NullPointerException.class)
  public void newClientWithNullUrlFails() throws NullPointerException, MinioException {
    URL url = null;
    new MinioClient(url);
    throw new RuntimeException(EXPECTED_EXCEPTION_DID_NOT_FIRE);
  }

  @Test(expected = InvalidEndpointException.class)
  public void testIsValidEndpoint1() throws MinioException {
    new MinioClient("minio-.example.com");
    throw new RuntimeException(EXPECTED_EXCEPTION_DID_NOT_FIRE);
  }

  @Test(expected = InvalidEndpointException.class)
  public void testIsValidEndpoint2() throws MinioException {
    new MinioClient("-minio.example.com");
    throw new RuntimeException(EXPECTED_EXCEPTION_DID_NOT_FIRE);
  }

  @Test(expected = InvalidEndpointException.class)
  public void testIsValidEndpoint3() throws MinioException {
    new MinioClient("minio..example.com");
    throw new RuntimeException(EXPECTED_EXCEPTION_DID_NOT_FIRE);
  }

  @Test(expected = InvalidEndpointException.class)
  public void testIsValidEndpoint4() throws MinioException {
    new MinioClient("minio._.com");
    throw new RuntimeException(EXPECTED_EXCEPTION_DID_NOT_FIRE);
  }

  @SuppressFBWarnings("NP")
  @Test(expected = MinioException.class)
  public void newClientWithNullStringFails() throws IllegalArgumentException, MinioException {
    String url = null;
    new MinioClient(url);
    throw new RuntimeException(EXPECTED_EXCEPTION_DID_NOT_FIRE);
  }

  @Test(expected = ErrorResponseException.class)
  public void testForbidden()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    MockWebServer server = new MockWebServer();
    server.enqueue(new MockResponse().setResponseCode(403));

    server.start();

    MinioClient client = new MinioClient(server.url(""));
    client.statObject(BUCKET, "key");

    throw new RuntimeException(EXPECTED_EXCEPTION_DID_NOT_FIRE);
  }

  @Test(expected = ErrorResponseException.class)
  public void getMissingObjectHeaders()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    MockWebServer server = new MockWebServer();
    server.enqueue(new MockResponse().setResponseCode(404));

    server.start();

    MinioClient client = new MinioClient(server.url(""));
    client.statObject(BUCKET, "key");

    throw new RuntimeException(EXPECTED_EXCEPTION_DID_NOT_FIRE);
  }

  @Test
  public void testGetObjectHeaders()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    MockWebServer server = new MockWebServer();
    MockResponse response = new MockResponse();
    response.setResponseCode(200);
    response.setHeader("Date", MON_29_JUN_2015_22_01_10_GMT);
    response.setHeader(CONTENT_LENGTH, "5080");
    response.setHeader(CONTENT_TYPE, APPLICATION_OCTET_STREAM);
    response.setHeader("ETag", "\"a670520d9d36833b3e28d1e4b73cbe22\"");
    response.setHeader(LAST_MODIFIED, MON_04_MAY_2015_07_58_51_GMT);

    server.enqueue(response);
    server.start();

    // build expected request
    ZonedDateTime expectedDate =
        ZonedDateTime.parse(MON_04_MAY_2015_07_58_51_GMT, Time.HTTP_HEADER_DATE_FORMAT);
    ObjectStat expectedStatInfo =
        new ObjectStat(
            BUCKET,
            "key",
            expectedDate,
            5080,
            "a670520d9d36833b3e28d1e4b73cbe22",
            APPLICATION_OCTET_STREAM);

    // get request
    MinioClient client = new MinioClient(server.url(""));
    ObjectStat objectStatInfo = client.statObject(BUCKET, "key");

    assertEquals(expectedStatInfo, objectStatInfo);
  }

  @Test(expected = InvalidExpiresRangeException.class)
  public void testPresignGetObjectFail()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    MockWebServer server = new MockWebServer();
    server.start();

    // get request
    MinioClient client = new MinioClient(server.url(""));
    client.presignedGetObject(BUCKET, "key", 604801);
  }

  @Test
  public void testPresignGetObject()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    MockWebServer server = new MockWebServer();
    server.start();

    // get request
    MinioClient client = new MinioClient(server.url(""));
    String presignedObjectUrl = client.presignedGetObject(BUCKET, "key");
    assertEquals(presignedObjectUrl.isEmpty(), false);
  }

  @Test
  public void testGetObjectUrl()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    MockWebServer server = new MockWebServer();
    server.start();

    // get request
    MinioClient client = new MinioClient(server.url(""));
    String objectUrl = client.getObjectUrl(BUCKET, "key");
    assertEquals(objectUrl.isEmpty(), false);
  }

  @Test
  public void testGetObject()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    MockWebServer server = new MockWebServer();
    MockResponse response = new MockResponse();
    final String expectedObject = HELLO_WORLD;

    response.addHeader("Date", "Sun, 05 Jun 2015 22:01:10 GMT");
    response.addHeader(CONTENT_LENGTH, "5080");
    response.addHeader(CONTENT_TYPE, APPLICATION_OCTET_STREAM);
    response.addHeader("ETag", MD5_HASH_STRING);
    response.addHeader(LAST_MODIFIED, MON_04_MAY_2015_07_58_51_GMT);
    response.setResponseCode(200);
    response.setBody(new Buffer().writeUtf8(expectedObject));

    server.enqueue(response);
    server.start();

    // get request
    MinioClient client = new MinioClient(server.url(""));
    InputStream object = client.getObject(BUCKET, "key");
    byte[] result = new byte[20];
    int read = object.read(result);
    result = Arrays.copyOf(result, read);
    assertEquals(expectedObject, new String(result, StandardCharsets.UTF_8));
  }

  @Test
  public void testPartialObject()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    final String expectedObject = HELLO;
    MockWebServer server = new MockWebServer();
    MockResponse response = new MockResponse();

    response.addHeader(CONTENT_LENGTH, "5");
    response.addHeader(CONTENT_TYPE, APPLICATION_OCTET_STREAM);
    response.addHeader("ETag", MD5_HASH_STRING);
    response.addHeader(LAST_MODIFIED, MON_04_MAY_2015_07_58_51_GMT);
    response.addHeader(ACCEPT_RANGES, BYTES);
    response.addHeader(CONTENT_RANGE, "0-4/11");
    response.setResponseCode(206);
    response.setBody(new Buffer().writeUtf8(expectedObject));

    server.enqueue(response);
    server.start();

    // get request
    MinioClient client = new MinioClient(server.url(""));
    InputStream object = client.getObject(BUCKET, "key", 0L, 5L);
    byte[] result = new byte[20];
    int read = object.read(result);
    result = Arrays.copyOf(result, read);
    assertEquals(expectedObject, new String(result, StandardCharsets.UTF_8));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testGetObjectOffsetIsNegativeReturnsError()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    final String expectedObject = HELLO;
    MockWebServer server = new MockWebServer();
    MockResponse response = new MockResponse();
    response.addHeader(CONTENT_LENGTH, "5");
    response.addHeader(CONTENT_TYPE, APPLICATION_OCTET_STREAM);
    response.addHeader("ETag", MD5_HASH_STRING);
    response.addHeader(LAST_MODIFIED, MON_04_MAY_2015_07_58_51_GMT);
    response.addHeader(ACCEPT_RANGES, BYTES);
    response.addHeader(CONTENT_RANGE, "0-4/11");
    response.setResponseCode(206);
    response.setBody(new Buffer().writeUtf8(expectedObject));

    server.enqueue(response);
    server.start();

    // get request
    MinioClient client = new MinioClient(server.url(""));
    client.getObject(BUCKET, "key", -1L, 5L);
    Assert.fail("Should of thrown an exception");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testGetObjectLengthIsZeroReturnsError()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    final String expectedObject = HELLO;
    MockWebServer server = new MockWebServer();
    MockResponse response = new MockResponse();

    response.addHeader(CONTENT_LENGTH, "5");
    response.addHeader(CONTENT_TYPE, APPLICATION_OCTET_STREAM);
    response.addHeader("ETag", MD5_HASH_STRING);
    response.addHeader(LAST_MODIFIED, MON_04_MAY_2015_07_58_51_GMT);
    response.addHeader(ACCEPT_RANGES, BYTES);
    response.addHeader(CONTENT_RANGE, "0-4/11");
    response.setResponseCode(206);
    response.setBody(new Buffer().writeUtf8(expectedObject));

    server.enqueue(response);
    server.start();

    // get request
    MinioClient client = new MinioClient(server.url(""));
    client.getObject(BUCKET, "key", 0L, 0L);
    Assert.fail("Should of thrown an exception");
  }

  /** test GetObjectWithOffset. */
  public void testGetObjectWithOffset()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    final String expectedObject = "world";
    MockWebServer server = new MockWebServer();
    MockResponse response = new MockResponse();

    response.addHeader(CONTENT_LENGTH, "6");
    response.addHeader(CONTENT_TYPE, APPLICATION_OCTET_STREAM);
    response.addHeader("ETag", MD5_HASH_STRING);
    response.addHeader(LAST_MODIFIED, MON_04_MAY_2015_07_58_51_GMT);
    response.addHeader(ACCEPT_RANGES, BYTES);
    response.addHeader(CONTENT_RANGE, "5-10/11");
    response.setResponseCode(206);
    response.setBody(new Buffer().writeUtf8(expectedObject));

    server.enqueue(response);
    server.start();

    // get request
    MinioClient client = new MinioClient(server.url(""));
    InputStream object = client.getObject(BUCKET, "key", 6);
    byte[] result = new byte[5];
    int read = object.read(result);
    result = Arrays.copyOf(result, read);
    assertEquals(expectedObject, new String(result, StandardCharsets.UTF_8));
  }

  @Test
  public void testListObjects()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    final String body =
        "<ListBucketResult xmlns=\"http://doc.s3.amazonaws.com/2006-03-01\"><Name>bucket</Name><Prefix></Prefix><Marker></Marker><MaxKeys>1000</MaxKeys><Delimiter></Delimiter><IsTruncated>false</IsTruncated><Contents><Key>key</Key><LastModified>2015-05-05T02:21:15.716Z</LastModified><ETag>\"5eb63bbbe01eeed093cb22bb8f5acdc3\"</ETag><Size>11</Size><StorageClass>STANDARD</StorageClass><Owner><ID>minio</ID><DisplayName>minio</DisplayName></Owner></Contents><Contents><Key>key2</Key><LastModified>2015-05-05T20:36:17.498Z</LastModified><ETag>\"2a60eaffa7a82804bdc682ce1df6c2d4\"</ETag><Size>1661</Size><StorageClass>STANDARD</StorageClass><Owner><ID>minio</ID><DisplayName>minio</DisplayName></Owner></Contents></ListBucketResult>";
    MockWebServer server = new MockWebServer();
    MockResponse response = new MockResponse();

    response.addHeader("Date", MON_29_JUN_2015_22_01_10_GMT);
    response.addHeader(CONTENT_LENGTH, "414");
    response.addHeader(CONTENT_TYPE, "application/xml");
    response.setBody(new Buffer().writeUtf8(body));
    response.setResponseCode(200);

    server.enqueue(response);
    server.start();

    MinioClient client = new MinioClient(server.url(""));
    Iterator<Result<Item>> objectsInBucket = client.listObjects(BUCKET).iterator();

    Item item = objectsInBucket.next().get();
    assertEquals("key", item.objectName());
    assertEquals(11, item.objectSize());
    assertEquals("STANDARD", item.storageClass());
    assertEquals("2015-05-05T02:21:15.716Z", item.lastModified().format(Time.RESPONSE_DATE_FORMAT));

    Owner owner = item.owner();
    assertEquals("minio", owner.id());
    assertEquals("minio", owner.displayName());
  }

  @Test
  public void testListBuckets()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException, ParseException {
    final String body =
        "<ListAllMyBucketsResult xmlns=\"http://doc.s3.amazonaws.com/2006-03-01\"><Owner><ID>minio</ID><DisplayName>minio</DisplayName></Owner><Buckets><Bucket><Name>bucket</Name><CreationDate>2015-05-05T20:35:51.410Z</CreationDate></Bucket><Bucket><Name>foo</Name><CreationDate>2015-05-05T20:35:47.170Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>";
    MockWebServer server = new MockWebServer();
    MockResponse response = new MockResponse();

    response.addHeader("Date", MON_29_JUN_2015_22_01_10_GMT);
    response.addHeader(CONTENT_LENGTH, "351");
    response.addHeader(CONTENT_TYPE, "application/xml");
    response.setBody(new Buffer().writeUtf8(body));
    response.setResponseCode(200);

    server.enqueue(response);
    server.start();

    MinioClient client = new MinioClient(server.url(""));
    Iterator<Bucket> buckets = client.listBuckets().iterator();

    Bucket bucket = buckets.next();
    assertEquals(BUCKET, bucket.name());
    assertEquals(
        "2015-05-05T20:35:51.410Z", bucket.creationDate().format(Time.RESPONSE_DATE_FORMAT));

    bucket = buckets.next();
    assertEquals("foo", bucket.name());
    assertEquals(
        "2015-05-05T20:35:47.170Z", bucket.creationDate().format(Time.RESPONSE_DATE_FORMAT));
  }

  @Test
  public void testBucketExists()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    MockWebServer server = new MockWebServer();
    MockResponse response = new MockResponse();

    response.addHeader("Date", MON_29_JUN_2015_22_01_10_GMT);
    response.setResponseCode(200);

    server.enqueue(response);
    server.start();

    MinioClient client = new MinioClient(server.url(""));
    boolean result = client.bucketExists(BUCKET);

    assertEquals(true, result);
  }

  @Test
  public void testBucketExistsFails()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    MockWebServer server = new MockWebServer();
    MockResponse response = new MockResponse();

    response.addHeader("Date", MON_29_JUN_2015_22_01_10_GMT);
    response.setResponseCode(404);

    server.enqueue(response);
    server.start();

    MinioClient client = new MinioClient(server.url(""));
    boolean result = client.bucketExists(BUCKET);

    assertEquals(false, result);
  }

  @Test
  public void testMakeBucket()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    MockWebServer server = new MockWebServer();
    MockResponse response1 = new MockResponse();
    MockResponse response2 = new MockResponse();

    response1.addHeader("Date", MON_29_JUN_2015_22_01_10_GMT);
    response1.setResponseCode(200);

    response2.addHeader("Date", MON_29_JUN_2015_22_01_10_GMT);
    response2.setResponseCode(200);

    server.enqueue(response1);
    server.enqueue(response2);
    server.start();

    MinioClient client = new MinioClient(server.url(""));
    client.makeBucket(BUCKET);
  }

  @Test(expected = InvalidResponseException.class)
  public void testMakeBucketFails()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    MockWebServer server = new MockWebServer();
    MockResponse response = new MockResponse();

    final ErrorResponse errResponse =
        new ErrorResponse(ErrorCode.BUCKET_ALREADY_EXISTS, null, null, "/bucket", "1", null);

    response.addHeader("Date", MON_29_JUN_2015_22_01_10_GMT);
    response.setResponseCode(409); // status conflict
    response.setBody(new Buffer().writeUtf8(errResponse.toString()));

    server.enqueue(response);
    server.start();

    MinioClient client = new MinioClient(server.url(""));
    client.makeBucket(BUCKET);

    throw new RuntimeException(EXPECTED_EXCEPTION_DID_NOT_FIRE);
  }

  @Test(expected = RegionConflictException.class)
  public void testMakeBucketRegionConflicts()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    MockWebServer server = new MockWebServer();
    server.start();

    MinioClient client = new MinioClient(server.url("").toString(), "foo", "bar", "us-east-1");
    client.makeBucket(BUCKET, "us-west-2");

    throw new RuntimeException(EXPECTED_EXCEPTION_DID_NOT_FIRE);
  }

  @Test
  public void testSigningKey()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    MockWebServer server = new MockWebServer();

    MockResponse response1 = new MockResponse();
    response1.setResponseCode(200);
    response1.setBody(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></LocationConstraint>");
    server.enqueue(response1);

    MockResponse response2 = new MockResponse();
    response2.addHeader("Date", MON_29_JUN_2015_22_01_10_GMT);
    response2.addHeader(CONTENT_LENGTH, "5080");
    response2.addHeader(CONTENT_TYPE, APPLICATION_OCTET_STREAM);
    response2.addHeader("ETag", "\"a670520d9d36833b3e28d1e4b73cbe22\"");
    response2.addHeader(LAST_MODIFIED, MON_04_MAY_2015_07_58_51_GMT);
    response2.setResponseCode(200);
    server.enqueue(response2);

    server.start();

    // build expected request
    ZonedDateTime expectedDate =
        ZonedDateTime.parse(MON_04_MAY_2015_07_58_51_GMT, Time.HTTP_HEADER_DATE_FORMAT);
    String contentType = APPLICATION_OCTET_STREAM;
    ObjectStat expectedStatInfo =
        new ObjectStat(
            BUCKET, "key", expectedDate, 5080, "a670520d9d36833b3e28d1e4b73cbe22", contentType);

    // get request
    MinioClient client = new MinioClient(server.url(""), "foo", "bar");

    ObjectStat objectStatInfo = client.statObject(BUCKET, "key");
    assertEquals(expectedStatInfo, objectStatInfo);
  }

  @Test
  public void testSetBucketPolicy()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    // Create Mock web server and mocked responses
    MockWebServer server = new MockWebServer();
    MockResponse response = new MockResponse();

    response.addHeader("Date", MON_29_JUN_2015_22_01_10_GMT);
    response.setResponseCode(200);

    server.enqueue(response);
    server.start();

    MinioClient client = new MinioClient(server.url(""));

    // Set the bucket policy for a bucket
    client.setBucketPolicy(BUCKET, "{\"Version\":\"2012-10-17\",\"Statement\":[]}");
  }

  @Test
  public void testGetBucketPolicy()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, XmlPullParserException,
          MinioException {
    // Create Mock web server and mocked responses
    MockWebServer server = new MockWebServer();
    MockResponse response = new MockResponse();

    String expectedPolicyString = "{\"Version\":\"2012-10-17\",\"Statement\":[]}";

    response.addHeader("Date", MON_29_JUN_2015_22_01_10_GMT);
    response.setResponseCode(200);
    response.setBody(expectedPolicyString);

    server.enqueue(response);
    server.start();

    MinioClient client = new MinioClient(server.url(""));

    // Get the bucket policy for the new bucket and check
    String policyString = client.getBucketPolicy(BUCKET);
    assertEquals(expectedPolicyString, policyString);
  }
}
