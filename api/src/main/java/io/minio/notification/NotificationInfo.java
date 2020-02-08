/*
 * MinIO Java SDK for Amazon S3 Compatible Cloud Storage,
 * (C) 2018 MinIO, Inc.
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

package io.minio.notification;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.util.Arrays;

@SuppressFBWarnings("UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD")
@JsonIgnoreProperties(ignoreUnknown = true)
public class NotificationInfo {
  @JsonProperty("Records")
  public NotificationEvent[] records;
  @JsonProperty("Err")
  public String err;


  @Override
  public String toString() {
    return "NotificationInfo{" + "records=" + Arrays.toString(records)
      + ", err='" + err + '\'' + '}';
  }
}

