/*
 * MinIO Java SDK for Amazon S3 Compatible Cloud Storage, (C) 2020 MinIO, Inc.
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
import io.minio.messages.Tags;
import java.util.Map;

/** Argument class of {@link MinioClient#setBucketTags}. */
public class SetBucketTagsArgs extends BucketArgs {
  private Tags tags;

  public Tags tags() {
    return tags;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Argument builder of {@link SetBucketTagsArgs}. */
  public static final class Builder extends BucketArgs.Builder<Builder, SetBucketTagsArgs> {
    private void validateTags(Tags tags) {
      validateNotNull(tags, "tags");
    }

    protected void validate(SetBucketTagsArgs args) {
      super.validate(args);
      validateTags(args.tags);
    }

    public Builder tags(Map<String, String> map) {
      validateNotNull(map, "map for tags");
      operations.add(args -> args.tags = Tags.newBucketTags(map));
      return this;
    }

    public Builder tags(Tags tags) {
      validateTags(tags);
      operations.add(args -> args.tags = tags);
      return this;
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof SetBucketTagsArgs)) return false;
    if (!super.equals(o)) return false;
    SetBucketTagsArgs that = (SetBucketTagsArgs) o;
    return Objects.equal(tags, that.tags);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(super.hashCode(), tags);
  }
}
