// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: content/service/v1/photo.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	pagination "kratos-blog/gen/api/go/common/pagination"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// 照片
type Photo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id          uint32  `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	Name        *string `protobuf:"bytes,2,opt,name=name,proto3,oneof" json:"name,omitempty"`
	Thumbnail   *string `protobuf:"bytes,3,opt,name=thumbnail,proto3,oneof" json:"thumbnail,omitempty"`
	Url         *string `protobuf:"bytes,5,opt,name=url,proto3,oneof" json:"url,omitempty"`
	Team        *string `protobuf:"bytes,6,opt,name=team,proto3,oneof" json:"team,omitempty"`
	Location    *string `protobuf:"bytes,7,opt,name=location,proto3,oneof" json:"location,omitempty"`
	Description *string `protobuf:"bytes,8,opt,name=description,proto3,oneof" json:"description,omitempty"`
	Likes       *int32  `protobuf:"varint,9,opt,name=likes,proto3,oneof" json:"likes,omitempty"`
	TakeTime    *string `protobuf:"bytes,10,opt,name=takeTime,proto3,oneof" json:"takeTime,omitempty"`
	CreateTime  *string `protobuf:"bytes,11,opt,name=createTime,proto3,oneof" json:"createTime,omitempty"`
}

func (x *Photo) Reset() {
	*x = Photo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_content_service_v1_photo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Photo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Photo) ProtoMessage() {}

func (x *Photo) ProtoReflect() protoreflect.Message {
	mi := &file_content_service_v1_photo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Photo.ProtoReflect.Descriptor instead.
func (*Photo) Descriptor() ([]byte, []int) {
	return file_content_service_v1_photo_proto_rawDescGZIP(), []int{0}
}

func (x *Photo) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *Photo) GetName() string {
	if x != nil && x.Name != nil {
		return *x.Name
	}
	return ""
}

func (x *Photo) GetThumbnail() string {
	if x != nil && x.Thumbnail != nil {
		return *x.Thumbnail
	}
	return ""
}

func (x *Photo) GetUrl() string {
	if x != nil && x.Url != nil {
		return *x.Url
	}
	return ""
}

func (x *Photo) GetTeam() string {
	if x != nil && x.Team != nil {
		return *x.Team
	}
	return ""
}

func (x *Photo) GetLocation() string {
	if x != nil && x.Location != nil {
		return *x.Location
	}
	return ""
}

func (x *Photo) GetDescription() string {
	if x != nil && x.Description != nil {
		return *x.Description
	}
	return ""
}

func (x *Photo) GetLikes() int32 {
	if x != nil && x.Likes != nil {
		return *x.Likes
	}
	return 0
}

func (x *Photo) GetTakeTime() string {
	if x != nil && x.TakeTime != nil {
		return *x.TakeTime
	}
	return ""
}

func (x *Photo) GetCreateTime() string {
	if x != nil && x.CreateTime != nil {
		return *x.CreateTime
	}
	return ""
}

// 回应 - 照片列表
type ListPhotoResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Items []*Photo `protobuf:"bytes,1,rep,name=items,proto3" json:"items,omitempty"`
	Total int32    `protobuf:"varint,2,opt,name=total,proto3" json:"total,omitempty"`
}

func (x *ListPhotoResponse) Reset() {
	*x = ListPhotoResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_content_service_v1_photo_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListPhotoResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListPhotoResponse) ProtoMessage() {}

func (x *ListPhotoResponse) ProtoReflect() protoreflect.Message {
	mi := &file_content_service_v1_photo_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListPhotoResponse.ProtoReflect.Descriptor instead.
func (*ListPhotoResponse) Descriptor() ([]byte, []int) {
	return file_content_service_v1_photo_proto_rawDescGZIP(), []int{1}
}

func (x *ListPhotoResponse) GetItems() []*Photo {
	if x != nil {
		return x.Items
	}
	return nil
}

func (x *ListPhotoResponse) GetTotal() int32 {
	if x != nil {
		return x.Total
	}
	return 0
}

// 请求 - 照片数据
type GetPhotoRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id uint32 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *GetPhotoRequest) Reset() {
	*x = GetPhotoRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_content_service_v1_photo_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetPhotoRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetPhotoRequest) ProtoMessage() {}

func (x *GetPhotoRequest) ProtoReflect() protoreflect.Message {
	mi := &file_content_service_v1_photo_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetPhotoRequest.ProtoReflect.Descriptor instead.
func (*GetPhotoRequest) Descriptor() ([]byte, []int) {
	return file_content_service_v1_photo_proto_rawDescGZIP(), []int{2}
}

func (x *GetPhotoRequest) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

// 请求 - 创建照片
type CreatePhotoRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Photo      *Photo  `protobuf:"bytes,1,opt,name=photo,proto3" json:"photo,omitempty"`
	OperatorId *uint32 `protobuf:"varint,2,opt,name=operatorId,proto3,oneof" json:"operatorId,omitempty"`
}

func (x *CreatePhotoRequest) Reset() {
	*x = CreatePhotoRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_content_service_v1_photo_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreatePhotoRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreatePhotoRequest) ProtoMessage() {}

func (x *CreatePhotoRequest) ProtoReflect() protoreflect.Message {
	mi := &file_content_service_v1_photo_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreatePhotoRequest.ProtoReflect.Descriptor instead.
func (*CreatePhotoRequest) Descriptor() ([]byte, []int) {
	return file_content_service_v1_photo_proto_rawDescGZIP(), []int{3}
}

func (x *CreatePhotoRequest) GetPhoto() *Photo {
	if x != nil {
		return x.Photo
	}
	return nil
}

func (x *CreatePhotoRequest) GetOperatorId() uint32 {
	if x != nil && x.OperatorId != nil {
		return *x.OperatorId
	}
	return 0
}

// 请求 - 更新照片
type UpdatePhotoRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id         uint32  `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	Photo      *Photo  `protobuf:"bytes,2,opt,name=photo,proto3" json:"photo,omitempty"`
	OperatorId *uint32 `protobuf:"varint,3,opt,name=operatorId,proto3,oneof" json:"operatorId,omitempty"`
}

func (x *UpdatePhotoRequest) Reset() {
	*x = UpdatePhotoRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_content_service_v1_photo_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdatePhotoRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdatePhotoRequest) ProtoMessage() {}

func (x *UpdatePhotoRequest) ProtoReflect() protoreflect.Message {
	mi := &file_content_service_v1_photo_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdatePhotoRequest.ProtoReflect.Descriptor instead.
func (*UpdatePhotoRequest) Descriptor() ([]byte, []int) {
	return file_content_service_v1_photo_proto_rawDescGZIP(), []int{4}
}

func (x *UpdatePhotoRequest) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *UpdatePhotoRequest) GetPhoto() *Photo {
	if x != nil {
		return x.Photo
	}
	return nil
}

func (x *UpdatePhotoRequest) GetOperatorId() uint32 {
	if x != nil && x.OperatorId != nil {
		return *x.OperatorId
	}
	return 0
}

// 请求 - 删除照片
type DeletePhotoRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id         uint32  `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	OperatorId *uint32 `protobuf:"varint,2,opt,name=operatorId,proto3,oneof" json:"operatorId,omitempty"`
}

func (x *DeletePhotoRequest) Reset() {
	*x = DeletePhotoRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_content_service_v1_photo_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeletePhotoRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeletePhotoRequest) ProtoMessage() {}

func (x *DeletePhotoRequest) ProtoReflect() protoreflect.Message {
	mi := &file_content_service_v1_photo_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeletePhotoRequest.ProtoReflect.Descriptor instead.
func (*DeletePhotoRequest) Descriptor() ([]byte, []int) {
	return file_content_service_v1_photo_proto_rawDescGZIP(), []int{5}
}

func (x *DeletePhotoRequest) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *DeletePhotoRequest) GetOperatorId() uint32 {
	if x != nil && x.OperatorId != nil {
		return *x.OperatorId
	}
	return 0
}

var File_content_service_v1_photo_proto protoreflect.FileDescriptor

var file_content_service_v1_photo_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2f, 0x76, 0x31, 0x2f, 0x70, 0x68, 0x6f, 0x74, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x12, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x76, 0x31, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x22, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x70, 0x61, 0x67, 0x69, 0x6e, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x70, 0x61, 0x67, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x97, 0x03, 0x0a, 0x05, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x12,
	0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x02, 0x69, 0x64, 0x12,
	0x17, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x88, 0x01, 0x01, 0x12, 0x21, 0x0a, 0x09, 0x74, 0x68, 0x75, 0x6d,
	0x62, 0x6e, 0x61, 0x69, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x48, 0x01, 0x52, 0x09, 0x74,
	0x68, 0x75, 0x6d, 0x62, 0x6e, 0x61, 0x69, 0x6c, 0x88, 0x01, 0x01, 0x12, 0x15, 0x0a, 0x03, 0x75,
	0x72, 0x6c, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x48, 0x02, 0x52, 0x03, 0x75, 0x72, 0x6c, 0x88,
	0x01, 0x01, 0x12, 0x17, 0x0a, 0x04, 0x74, 0x65, 0x61, 0x6d, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09,
	0x48, 0x03, 0x52, 0x04, 0x74, 0x65, 0x61, 0x6d, 0x88, 0x01, 0x01, 0x12, 0x1f, 0x0a, 0x08, 0x6c,
	0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x48, 0x04, 0x52,
	0x08, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x88, 0x01, 0x01, 0x12, 0x25, 0x0a, 0x0b,
	0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x08, 0x20, 0x01, 0x28,
	0x09, 0x48, 0x05, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x88, 0x01, 0x01, 0x12, 0x19, 0x0a, 0x05, 0x6c, 0x69, 0x6b, 0x65, 0x73, 0x18, 0x09, 0x20, 0x01,
	0x28, 0x05, 0x48, 0x06, 0x52, 0x05, 0x6c, 0x69, 0x6b, 0x65, 0x73, 0x88, 0x01, 0x01, 0x12, 0x1f,
	0x0a, 0x08, 0x74, 0x61, 0x6b, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09,
	0x48, 0x07, 0x52, 0x08, 0x74, 0x61, 0x6b, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x88, 0x01, 0x01, 0x12,
	0x23, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x18, 0x0b, 0x20,
	0x01, 0x28, 0x09, 0x48, 0x08, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d,
	0x65, 0x88, 0x01, 0x01, 0x42, 0x07, 0x0a, 0x05, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x42, 0x0c, 0x0a,
	0x0a, 0x5f, 0x74, 0x68, 0x75, 0x6d, 0x62, 0x6e, 0x61, 0x69, 0x6c, 0x42, 0x06, 0x0a, 0x04, 0x5f,
	0x75, 0x72, 0x6c, 0x42, 0x07, 0x0a, 0x05, 0x5f, 0x74, 0x65, 0x61, 0x6d, 0x42, 0x0b, 0x0a, 0x09,
	0x5f, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x0e, 0x0a, 0x0c, 0x5f, 0x64, 0x65,
	0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x08, 0x0a, 0x06, 0x5f, 0x6c, 0x69,
	0x6b, 0x65, 0x73, 0x42, 0x0b, 0x0a, 0x09, 0x5f, 0x74, 0x61, 0x6b, 0x65, 0x54, 0x69, 0x6d, 0x65,
	0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x22,
	0x5a, 0x0a, 0x11, 0x4c, 0x69, 0x73, 0x74, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2f, 0x0a, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x52, 0x05,
	0x69, 0x74, 0x65, 0x6d, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x22, 0x21, 0x0a, 0x0f, 0x47,
	0x65, 0x74, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e,
	0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x02, 0x69, 0x64, 0x22, 0x79,
	0x0a, 0x12, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x2f, 0x0a, 0x05, 0x70, 0x68, 0x6f, 0x74, 0x6f, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x52, 0x05,
	0x70, 0x68, 0x6f, 0x74, 0x6f, 0x12, 0x23, 0x0a, 0x0a, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f,
	0x72, 0x49, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x48, 0x00, 0x52, 0x0a, 0x6f, 0x70, 0x65,
	0x72, 0x61, 0x74, 0x6f, 0x72, 0x49, 0x64, 0x88, 0x01, 0x01, 0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x6f,
	0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x49, 0x64, 0x22, 0x89, 0x01, 0x0a, 0x12, 0x55, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x02, 0x69, 0x64,
	0x12, 0x2f, 0x0a, 0x05, 0x70, 0x68, 0x6f, 0x74, 0x6f, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x19, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x52, 0x05, 0x70, 0x68, 0x6f, 0x74,
	0x6f, 0x12, 0x23, 0x0a, 0x0a, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x49, 0x64, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0d, 0x48, 0x00, 0x52, 0x0a, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f,
	0x72, 0x49, 0x64, 0x88, 0x01, 0x01, 0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x6f, 0x70, 0x65, 0x72, 0x61,
	0x74, 0x6f, 0x72, 0x49, 0x64, 0x22, 0x58, 0x0a, 0x12, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x50,
	0x68, 0x6f, 0x74, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x02, 0x69, 0x64, 0x12, 0x23, 0x0a, 0x0a, 0x6f,
	0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x49, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x48,
	0x00, 0x52, 0x0a, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x49, 0x64, 0x88, 0x01, 0x01,
	0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x49, 0x64, 0x32,
	0xa6, 0x03, 0x0a, 0x0c, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x12, 0x4f, 0x0a, 0x09, 0x4c, 0x69, 0x73, 0x74, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x12, 0x19, 0x2e,
	0x70, 0x61, 0x67, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x50, 0x61, 0x67, 0x69, 0x6e,
	0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x25, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x65,
	0x6e, 0x74, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69,
	0x73, 0x74, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22,
	0x00, 0x12, 0x4c, 0x0a, 0x08, 0x47, 0x65, 0x74, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x12, 0x23, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e,
	0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x19, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x22, 0x00, 0x12,
	0x52, 0x0a, 0x0b, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x12, 0x26,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x2e, 0x76, 0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x19, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
	0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x68, 0x6f, 0x74,
	0x6f, 0x22, 0x00, 0x12, 0x52, 0x0a, 0x0b, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x68, 0x6f,
	0x74, 0x6f, 0x12, 0x26, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x68,
	0x6f, 0x74, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x19, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x65, 0x6e, 0x74, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x2e,
	0x50, 0x68, 0x6f, 0x74, 0x6f, 0x22, 0x00, 0x12, 0x4f, 0x0a, 0x0b, 0x44, 0x65, 0x6c, 0x65, 0x74,
	0x65, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x12, 0x26, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
	0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65, 0x6c, 0x65,
	0x74, 0x65, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x22, 0x00, 0x42, 0x2e, 0x5a, 0x2c, 0x6b, 0x72, 0x61, 0x74,
	0x6f, 0x73, 0x2d, 0x62, 0x6c, 0x6f, 0x67, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x67, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x2f, 0x76, 0x31, 0x3b, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_content_service_v1_photo_proto_rawDescOnce sync.Once
	file_content_service_v1_photo_proto_rawDescData = file_content_service_v1_photo_proto_rawDesc
)

func file_content_service_v1_photo_proto_rawDescGZIP() []byte {
	file_content_service_v1_photo_proto_rawDescOnce.Do(func() {
		file_content_service_v1_photo_proto_rawDescData = protoimpl.X.CompressGZIP(file_content_service_v1_photo_proto_rawDescData)
	})
	return file_content_service_v1_photo_proto_rawDescData
}

var file_content_service_v1_photo_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_content_service_v1_photo_proto_goTypes = []interface{}{
	(*Photo)(nil),                    // 0: content.service.v1.Photo
	(*ListPhotoResponse)(nil),        // 1: content.service.v1.ListPhotoResponse
	(*GetPhotoRequest)(nil),          // 2: content.service.v1.GetPhotoRequest
	(*CreatePhotoRequest)(nil),       // 3: content.service.v1.CreatePhotoRequest
	(*UpdatePhotoRequest)(nil),       // 4: content.service.v1.UpdatePhotoRequest
	(*DeletePhotoRequest)(nil),       // 5: content.service.v1.DeletePhotoRequest
	(*pagination.PagingRequest)(nil), // 6: pagination.PagingRequest
	(*emptypb.Empty)(nil),            // 7: google.protobuf.Empty
}
var file_content_service_v1_photo_proto_depIdxs = []int32{
	0, // 0: content.service.v1.ListPhotoResponse.items:type_name -> content.service.v1.Photo
	0, // 1: content.service.v1.CreatePhotoRequest.photo:type_name -> content.service.v1.Photo
	0, // 2: content.service.v1.UpdatePhotoRequest.photo:type_name -> content.service.v1.Photo
	6, // 3: content.service.v1.PhotoService.ListPhoto:input_type -> pagination.PagingRequest
	2, // 4: content.service.v1.PhotoService.GetPhoto:input_type -> content.service.v1.GetPhotoRequest
	3, // 5: content.service.v1.PhotoService.CreatePhoto:input_type -> content.service.v1.CreatePhotoRequest
	4, // 6: content.service.v1.PhotoService.UpdatePhoto:input_type -> content.service.v1.UpdatePhotoRequest
	5, // 7: content.service.v1.PhotoService.DeletePhoto:input_type -> content.service.v1.DeletePhotoRequest
	1, // 8: content.service.v1.PhotoService.ListPhoto:output_type -> content.service.v1.ListPhotoResponse
	0, // 9: content.service.v1.PhotoService.GetPhoto:output_type -> content.service.v1.Photo
	0, // 10: content.service.v1.PhotoService.CreatePhoto:output_type -> content.service.v1.Photo
	0, // 11: content.service.v1.PhotoService.UpdatePhoto:output_type -> content.service.v1.Photo
	7, // 12: content.service.v1.PhotoService.DeletePhoto:output_type -> google.protobuf.Empty
	8, // [8:13] is the sub-list for method output_type
	3, // [3:8] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_content_service_v1_photo_proto_init() }
func file_content_service_v1_photo_proto_init() {
	if File_content_service_v1_photo_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_content_service_v1_photo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Photo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_content_service_v1_photo_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListPhotoResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_content_service_v1_photo_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetPhotoRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_content_service_v1_photo_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreatePhotoRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_content_service_v1_photo_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdatePhotoRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_content_service_v1_photo_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeletePhotoRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_content_service_v1_photo_proto_msgTypes[0].OneofWrappers = []interface{}{}
	file_content_service_v1_photo_proto_msgTypes[3].OneofWrappers = []interface{}{}
	file_content_service_v1_photo_proto_msgTypes[4].OneofWrappers = []interface{}{}
	file_content_service_v1_photo_proto_msgTypes[5].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_content_service_v1_photo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_content_service_v1_photo_proto_goTypes,
		DependencyIndexes: file_content_service_v1_photo_proto_depIdxs,
		MessageInfos:      file_content_service_v1_photo_proto_msgTypes,
	}.Build()
	File_content_service_v1_photo_proto = out.File
	file_content_service_v1_photo_proto_rawDesc = nil
	file_content_service_v1_photo_proto_goTypes = nil
	file_content_service_v1_photo_proto_depIdxs = nil
}
