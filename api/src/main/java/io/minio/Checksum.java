/*
 * MinIO Java SDK for Amazon S3 Compatible Cloud Storage, (C) 2025 MinIO, Inc.
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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/** Collection of checksum algorithms. */
public class Checksum {
  /** Checksum Algorithm. */
  public static enum Algorithm {
    CRC32,
    CRC32C,
    CRC64NVME,
    SHA1,
    SHA256;
  }

  public abstract static class Hasher {
    public abstract void update(byte b[], int off, int len);

    public abstract byte[] sum();

    public String sumAsBase64String() {
      return Base64.getEncoder().encodeToString(sum());
    }

    public String sumAsHexString() {
      byte[] sum = sum();
      StringBuilder builder = new StringBuilder();
      for (byte b : sum) builder.append(String.format("%02x", b));
      return builder.toString();
    }
  }

  //  {
  //    CRC32 hasher = new CRC32();
  //    hasher.update(value);
  //    System.out.println("crc32: " + hasher.getValue());
  //  }
  //
  /** CRC32 checksum is java.util.zip.CRC32 compatible to Hasher. */
  public static class CRC32 extends Hasher {
    private java.util.zip.CRC32 hasher;

    public CRC32() {
      hasher = new java.util.zip.CRC32();
    }

    @Override
    public void update(byte b[], int off, int len) {
      hasher.update(b, off, len);
    }

    @Override
    public byte[] sum() {
      int value = (int) hasher.getValue();
      return new byte[] {
        (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value
      };
    }

    @Override
    public String toString() {
      return "CRC32{" + this.sumAsHexString() + "}";
    }
  }

  //  {
  //    CRC32C hasher = new CRC32C();
  //    hasher.update(value);
  //    System.out.println("crc32c: " + hasher.getValue());
  //  }
  //
  /** CRC32C checksum. */
  public static class CRC32C extends Hasher implements java.util.zip.Checksum {
    private static final int[] CRC32C_TABLE = new int[256];
    private int crc = 0xFFFFFFFF;

    static {
      for (int i = 0; i < 256; i++) {
        int crc = i;
        for (int j = 0; j < 8; j++) {
          crc = (crc >>> 1) ^ ((crc & 1) != 0 ? 0x82F63B78 : 0);
        }
        CRC32C_TABLE[i] = crc;
      }
    }

    @Override
    public void update(int b) {
      crc = CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >>> 8);
    }

    @Override
    public void update(byte[] b, int off, int len) {
      for (int i = off; i < off + len; i++) {
        update(b[i]);
      }
    }

    @Override
    public long getValue() {
      return (crc ^ 0xFFFFFFFFL) & 0xFFFFFFFFL;
    }

    @Override
    public void reset() {
      crc = 0xFFFFFFFF;
    }

    @Override
    public byte[] sum() {
      int value = (int) this.getValue();
      return new byte[] {
        (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value
      };
    }

    @Override
    public String toString() {
      return "CRC32C{" + this.sumAsHexString() + "}";
    }
  }

  //  {
  //    CRC64NVME hasher = new CRC64NVME();
  //    hasher.update(value);
  //    System.out.println("crc64nvme: " + hasher.getValue());
  //  }
  //
  /** CRC64NVME checksum logic copied from https://github.com/minio/crc64nvme. */
  public static class CRC64NVME extends Hasher implements java.util.zip.Checksum {
    private static final long[] CRC64_TABLE = new long[256];
    private static final long[][] SLICING8_TABLE_NVME = new long[8][256];

    static {
      long polynomial = 0x9A6C9329AC4BC9B5L;
      for (int i = 0; i < 256; i++) {
        long crc = i;
        for (int j = 0; j < 8; j++) {
          if ((crc & 1) == 1) {
            crc = (crc >>> 1) ^ polynomial;
          } else {
            crc >>>= 1;
          }
        }
        CRC64_TABLE[i] = crc;
      }

      SLICING8_TABLE_NVME[0] = CRC64_TABLE;
      for (int i = 0; i < 256; i++) {
        long crc = CRC64_TABLE[i];
        for (int j = 1; j < 8; j++) {
          crc = CRC64_TABLE[(int) crc & 0xFF] ^ (crc >>> 8);
          SLICING8_TABLE_NVME[j][i] = crc;
        }
      }
    }

    private long crc = 0;

    public CRC64NVME() {}

    @Override
    public void update(byte[] p, int off, int len) {
      ByteBuffer byteBuffer = ByteBuffer.wrap(p, off, len);
      byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
      int offset = byteBuffer.position();

      crc = ~crc;
      while (p.length >= 64 && (p.length - offset) > 8) {
        long value = byteBuffer.getLong();
        crc ^= value;
        crc =
            SLICING8_TABLE_NVME[7][(int) (crc & 0xFF)]
                ^ SLICING8_TABLE_NVME[6][(int) ((crc >>> 8) & 0xFF)]
                ^ SLICING8_TABLE_NVME[5][(int) ((crc >>> 16) & 0xFF)]
                ^ SLICING8_TABLE_NVME[4][(int) ((crc >>> 24) & 0xFF)]
                ^ SLICING8_TABLE_NVME[3][(int) ((crc >>> 32) & 0xFF)]
                ^ SLICING8_TABLE_NVME[2][(int) ((crc >>> 40) & 0xFF)]
                ^ SLICING8_TABLE_NVME[1][(int) ((crc >>> 48) & 0xFF)]
                ^ SLICING8_TABLE_NVME[0][(int) (crc >>> 56)];
        offset = byteBuffer.position();
      }

      for (; offset < len; offset++) {
        crc = CRC64_TABLE[(int) ((crc ^ (long) p[offset]) & 0xFF)] ^ (crc >>> 8);
      }

      crc = ~crc;
    }

    @Override
    public void update(int b) {
      update(new byte[] {(byte) b}, 0, 1);
    }

    @Override
    public long getValue() {
      return crc;
    }

    @Override
    public void reset() {
      crc = 0;
    }

    @Override
    public byte[] sum() {
      long value = this.getValue();
      return new byte[] {
        (byte) (value >>> 56),
        (byte) (value >>> 48),
        (byte) (value >>> 40),
        (byte) (value >>> 32),
        (byte) (value >>> 24),
        (byte) (value >>> 16),
        (byte) (value >>> 8),
        (byte) value
      };
    }

    @Override
    public String toString() {
      return "CRC64NVME{" + this.sumAsHexString() + "}";
    }
  }

  //  {
  //    MessageDigest hasher = MessageDigest.getInstance("SHA-1");
  //    hasher.update(value);
  //    System.out.println("sha-1: " + Arrays.toString(toPositiveValues(hasher.digest())));
  //  }
  //
  public static class SHA1 extends Hasher {
    MessageDigest hasher;

    public SHA1() throws NoSuchAlgorithmException {
      this.hasher = MessageDigest.getInstance("SHA-1");
    }

    public void update(byte b[], int off, int len) {
      hasher.update(b, off, len);
    }

    public byte[] sum() {
      return hasher.digest();
    }

    @Override
    public String toString() {
      return "SHA1{" + this.sumAsHexString() + "}";
    }
  }

  //  {
  //    MessageDigest hasher = MessageDigest.getInstance("SHA-256");
  //    hasher.update(value);
  //    System.out.println("sha-256: " + Arrays.toString(toPositiveValues(hasher.digest())));
  //  }
  public static class SHA256 extends Hasher {
    MessageDigest hasher;

    public SHA256() throws NoSuchAlgorithmException {
      this.hasher = MessageDigest.getInstance("SHA-256");
    }

    public void update(byte b[], int off, int len) {
      hasher.update(b, off, len);
    }

    public byte[] sum() {
      return hasher.digest();
    }

    @Override
    public String toString() {
      return "SHA256{" + this.sumAsHexString() + "}";
    }
  }
}
