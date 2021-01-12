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
import io.minio.messages.MetricsConfiguration;

/** Argument class of {@link MinioClient#setBucketMetricsConfiguration}. */
public class SetBucketMetricsConfigurationArgs extends BucketArgs {
  private MetricsConfiguration config;

  public MetricsConfiguration config() {
    return config;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Argument builder of {@link SetBucketMetricsConfigurationArgs}. */
  public static final class Builder extends BucketArgs.Builder<Builder, SetBucketMetricsConfigurationArgs> {
    private void validateConfig(MetricsConfiguration config) {
      validateNotNull(config, "metrics configuration");
    }

    protected void validate(SetBucketMetricsConfigurationArgs args) {
      super.validate(args);
      validateConfig(args.config);
    }

    public Builder config(MetricsConfiguration config) {
      validateConfig(config);
      operations.add(args -> args.config = config);
      return this;
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof SetBucketMetricsConfigurationArgs)) return false;
    if (!super.equals(o)) return false;
    SetBucketMetricsConfigurationArgs that = (SetBucketMetricsConfigurationArgs) o;
    return Objects.equal(config, that.config);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(super.hashCode(), config);
  }
}
