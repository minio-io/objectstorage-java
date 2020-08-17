/*
 * MinIO Java SDK for Amazon S3 Compatible Cloud Storage, (C) 2020 MinIO, Inc.
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

package io.minio.credentials;

import java.util.Arrays;
import java.util.List;
import javax.annotation.Nonnull;

/** Chained credential provider work with list of credential providers. */
public class ChainProvider implements Provider {
  private final List<Provider> providers;
  private Provider currentProvider;
  private Credentials credentials;

  public ChainProvider(@Nonnull Provider... providers) {
    this.providers = Arrays.asList(providers);
  }

  @Override
  public Credentials fetch() {
    if (this.credentials != null && !this.credentials.isExpired()) {
      return this.credentials;
    }

    Credentials credentials = null;

    if (currentProvider != null) {
      try {
        credentials = currentProvider.fetch();
      } catch (IllegalStateException e) {
        // Ignore and fallback to iteration.
      }
    }

    if (credentials != null) {
      synchronized (this) {
        this.credentials = credentials;
      }

      return this.credentials;
    }

    for (Provider provider : providers) {
      try {
        credentials = provider.fetch();
        synchronized (this) {
          this.currentProvider = provider;
        }
        break;
      } catch (IllegalStateException e) {
        // Ignore and continue to next iteration.
      }
    }

    if (credentials == null) {
      throw new IllegalStateException("All providers fail to fetch credentials");
    }

    synchronized (this) {
      this.credentials = credentials;
    }

    return this.credentials;
  }
}
