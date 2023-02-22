// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: common/conf/tracer.proto

package conf

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// 链路追踪
type Trace struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Batcher  string  `protobuf:"bytes,1,opt,name=batcher,proto3" json:"batcher,omitempty"`   // jaeger或者zipkin
	Endpoint string  `protobuf:"bytes,2,opt,name=endpoint,proto3" json:"endpoint,omitempty"` // 端口
	Sampler  float64 `protobuf:"fixed64,3,opt,name=sampler,proto3" json:"sampler,omitempty"` // 采样率，默认：1.0
	Env      string  `protobuf:"bytes,4,opt,name=env,proto3" json:"env,omitempty"`           // 运行环境：dev、debug、product
}

func (x *Trace) Reset() {
	*x = Trace{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_conf_tracer_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Trace) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Trace) ProtoMessage() {}

func (x *Trace) ProtoReflect() protoreflect.Message {
	mi := &file_common_conf_tracer_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Trace.ProtoReflect.Descriptor instead.
func (*Trace) Descriptor() ([]byte, []int) {
	return file_common_conf_tracer_proto_rawDescGZIP(), []int{0}
}

func (x *Trace) GetBatcher() string {
	if x != nil {
		return x.Batcher
	}
	return ""
}

func (x *Trace) GetEndpoint() string {
	if x != nil {
		return x.Endpoint
	}
	return ""
}

func (x *Trace) GetSampler() float64 {
	if x != nil {
		return x.Sampler
	}
	return 0
}

func (x *Trace) GetEnv() string {
	if x != nil {
		return x.Env
	}
	return ""
}

var File_common_conf_tracer_proto protoreflect.FileDescriptor

var file_common_conf_tracer_proto_rawDesc = []byte{
	0x0a, 0x18, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x2f, 0x74, 0x72,
	0x61, 0x63, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x63, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x22, 0x69, 0x0a, 0x05, 0x54, 0x72, 0x61, 0x63, 0x65,
	0x12, 0x18, 0x0a, 0x07, 0x62, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x62, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x12, 0x1a, 0x0a, 0x08, 0x65, 0x6e,
	0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x65, 0x6e,
	0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65,
	0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x01, 0x52, 0x07, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x72,
	0x12, 0x10, 0x0a, 0x03, 0x65, 0x6e, 0x76, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x65,
	0x6e, 0x76, 0x42, 0x29, 0x5a, 0x27, 0x6b, 0x72, 0x61, 0x74, 0x6f, 0x73, 0x2d, 0x62, 0x6c, 0x6f,
	0x67, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x6f, 0x2f, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x3b, 0x63, 0x6f, 0x6e, 0x66, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_common_conf_tracer_proto_rawDescOnce sync.Once
	file_common_conf_tracer_proto_rawDescData = file_common_conf_tracer_proto_rawDesc
)

func file_common_conf_tracer_proto_rawDescGZIP() []byte {
	file_common_conf_tracer_proto_rawDescOnce.Do(func() {
		file_common_conf_tracer_proto_rawDescData = protoimpl.X.CompressGZIP(file_common_conf_tracer_proto_rawDescData)
	})
	return file_common_conf_tracer_proto_rawDescData
}

var file_common_conf_tracer_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_common_conf_tracer_proto_goTypes = []interface{}{
	(*Trace)(nil), // 0: common.conf.Trace
}
var file_common_conf_tracer_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_common_conf_tracer_proto_init() }
func file_common_conf_tracer_proto_init() {
	if File_common_conf_tracer_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_common_conf_tracer_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Trace); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_common_conf_tracer_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_common_conf_tracer_proto_goTypes,
		DependencyIndexes: file_common_conf_tracer_proto_depIdxs,
		MessageInfos:      file_common_conf_tracer_proto_msgTypes,
	}.Build()
	File_common_conf_tracer_proto = out.File
	file_common_conf_tracer_proto_rawDesc = nil
	file_common_conf_tracer_proto_goTypes = nil
	file_common_conf_tracer_proto_depIdxs = nil
}
