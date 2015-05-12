/*
 * Minimal Object Storage Library, (C) 2015 Minio, Inc.
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

package io.minio.objectstorage.client;

import io.minio.objectstorage.client.messages.ListAllMyBucketsResult;
import org.junit.Ignore;
import org.junit.Test;
import org.xmlpull.v1.XmlPullParserException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class IntegrationTest {

    @Test
    @Ignore
    public void testSigning() throws IOException, XmlPullParserException {
        HttpClient client = (HttpClient) Clients.getClient("https://s3-us-west-2.amazonaws.com");
        client.setKeys("REDACTED", "REDACTED");
//        client.enableLogging();
        ListAllMyBucketsResult allMyBucketsResult = client.listBuckets();
        System.out.println(allMyBucketsResult);
    }

    @Test
    @Ignore
    public void testClient() throws IOException, XmlPullParserException {
        HttpClient client = (HttpClient)Clients.getClient("https://s3-us-west-2.amazonaws.com");
        client.setKeys("REDACTED", "REDACTED");
        client.enableLogging();
//        client.createBucket("foo", Client.ACL_PUBLIC_READ_WRITE);

        String inputString = "hello world";
        ByteArrayInputStream data = new ByteArrayInputStream(inputString.getBytes("UTF-8"));
        client.createObject("foo", "bar", "application/octet-stream", 11, data);

        InputStream object = client.getObject("foo", "bar");
        byte[] result = new byte[11];
        int read = object.read(result);
        assertEquals(read, 11);
        object.close();
        String resultString = new String(result, "UTF-8");
        assertEquals(inputString, resultString);

        byte[] largeObject = new byte[10 * 1024 * 1024];
        for (int i = 0; i < 10 * 1024 * 1024; i++) {
            largeObject[i] = 'a';
        }

        InputStream largeObjectStream = new ByteArrayInputStream(largeObject);
        client.createObject("foo", "bar2", "application/octet-stream", largeObject.length, largeObjectStream);

        InputStream object1 = client.getObject("foo", "bar2");
        byte[] largeResult = new byte[10 * 1024 * 1024];
        int amountRead = 0;
        while (amountRead != largeResult.length) {
            amountRead += object1.read(largeResult, amountRead, largeResult.length - amountRead);
        }
        assertEquals(amountRead, largeResult.length);

        assertArrayEquals(largeObject, largeResult);
    }
}
