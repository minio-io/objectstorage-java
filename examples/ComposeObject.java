/*
 * Minio Java SDK for Amazon S3 Compatible Cloud Storage, (C) 2019 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import io.minio.ComposeObjectArgs;
import io.minio.ComposeSourceArgs;
import io.minio.MinioClient;
import io.minio.errors.MinioException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class ComposeObject {
  /** MinioClient.composeObject() example. */
  public static void main(String[] args)
      throws IOException, NoSuchAlgorithmException, InvalidKeyException {
    try {
      /* play.minio.io for test and development. */
      MinioClient minioClient =
          new MinioClient(
              "https://play.min.io:9000",
              "Q3AM3UQ867SPQQA43P2F",
              "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG");

      // Create a ComposeSourceArgs to compose Object.
      ComposeSourceArgs s1 =
          ComposeSourceArgs.builder()
              .srcBucket("my-bucketname-one")
              .srcObject("my-objectname-one")
              .build();
      ComposeSourceArgs s2 =
          ComposeSourceArgs.builder()
              .srcBucket("my-bucketname-two")
              .srcObject("my-objectname-two")
              .build();
      ComposeSourceArgs s3 =
          ComposeSourceArgs.builder()
              .srcBucket("my-bucketname-three")
              .srcObject("my-objectname-three")
              .build();

      // Adding the ComposeSourceArgs to an ArrayList
      List<ComposeSourceArgs> sourceObjectList = new ArrayList<ComposeSourceArgs>();
      sourceObjectList.add(s1);
      sourceObjectList.add(s2);
      sourceObjectList.add(s3);

      minioClient.composeObject(
          ComposeObjectArgs.builder()
              .bucket("my-destination-bucket")
              .object("my-destination-object")
              .sources(sourceObjectList)
              .build());
      System.out.println("Object Composed successfully");
    } catch (MinioException e) {
      System.out.println("Error occurred: " + e);
    }
  }
}
