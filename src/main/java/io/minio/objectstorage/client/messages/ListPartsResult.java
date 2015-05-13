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

package io.minio.objectstorage.client.messages;

import com.google.api.client.util.Key;

import java.util.List;

public class ListPartsResult extends XmlEntity {
    @Key("Bucket")
    private String Bucket;
    @Key("Key")
    private String Key;
    @Key("Initiator")
    private Initiator initiator;
    @Key("Owner")
    private Owner owner;
    @Key("StorageClass")
    private String storageClass;
    @Key("PartNumberMarker")
    private Integer PartNumberMarker;
    @Key("NextPartNumberMarker")
    private Integer NextPartNumberMarker;
    @Key("MaxParts")
    private Integer MaxParts;
    @Key("IsTruncated")
    private boolean IsTruncated;
    @Key("Part")
    private List<Part> Part;

    public ListPartsResult() {
	super();
	this.name = "ListPartsResult";
    }

    public String getBucket() {
	return Bucket;
    }

    public void setBucket(String bucket) {
	Bucket = bucket;
    }

    public String getKey() {
	return Key;
    }

    public void setKey(String key) {
	Key = key;
    }

    public String getStorageClass() {
	return storageClass;
    }

    public void setStorageClass(String storageClass) {
	this.storageClass = storageClass;
    }

    public Initiator getInitiator() {
	return initiator;
    }

    public void setInitiator(Initiator initiator) {
	this.initiator = initiator;
    }

    public Owner getOwner() {
	return owner;
    }

    public void setOwner(Owner owner) {
	this.owner = owner;
    }

    public Integer getMaxParts() {
        return MaxParts;
    }

    public void setMaxParts(Integer maxParts) {
        MaxParts = maxParts;
    }

    public boolean isTruncated() {
        return IsTruncated;
    }

    public void setIsTruncated(boolean isTruncated) {
        IsTruncated = isTruncated;
    }

    public Integer getPartNumberMarker() {
	return PartNumberMarker;
    }

    public void setPartNumberMarker(Integer partNumberMarker) {
	PartNumberMarker = partNumberMarker;
    }

    public Integer getNextPartNumberMarker() {
	return NextPartNumberMarker;
    }

    public void setNextPartNumberMarker(Integer nextPartNumberMarker) {
	NextPartNumberMarker = nextPartNumberMarker;
    }

    public List<Part> getParts() {
        return Part;
    }

    public void setParts(List<Part> parts) {
        Part = parts;
    }

}
