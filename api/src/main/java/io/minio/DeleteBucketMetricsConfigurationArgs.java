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

import com.google.common.base.Objects;

/** Argument class of {@link MinioClient#deleteBucketMetricsConfiguration}. */
public class DeleteBucketMetricsConfigurationArgs extends BucketArgs {
  private String id;
  
  public String id() {
    return id;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Argument builder of {@link DeleteBucketMetricsConfigurationArgs}. */
  public static final class Builder extends BucketArgs.Builder<Builder, DeleteBucketMetricsConfigurationArgs> {
    public Builder id(String id) {
      validateNotEmptyString(id, "id");
      operations.add(args -> args.id = id);
      return this;
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof DeleteBucketMetricsConfigurationArgs)) return false;
    if (!super.equals(o)) return false;
    DeleteBucketMetricsConfigurationArgs that = (DeleteBucketMetricsConfigurationArgs) o;
    return Objects.equal(id, that.id);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(super.hashCode(), id);
  }
}
