/*
 * MinIO Java SDK for Amazon S3 Compatible Cloud Storage,
 * (C) 2022 MinIO, Inc.
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

package io.minio.admin.info;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Objects contains the number of objects
 *
 * @see <a https://github.com/minio/madmin-go/blob/main/info-commands.go#L292">info-commands.go</a>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Objects {
  @JsonProperty("count")
  private Integer count;

  @JsonProperty("error")
  private String error;

  public Integer count() {
    return count;
  }

  public String error() {
    return error;
  }
}
