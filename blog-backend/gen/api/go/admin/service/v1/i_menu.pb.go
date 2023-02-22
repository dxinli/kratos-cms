// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: admin/service/v1/i_menu.proto

package v1

import (
	_ "github.com/google/gnostic/openapiv3"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	pagination "kratos-blog/gen/api/go/common/pagination"
	v1 "kratos-blog/gen/api/go/content/service/v1"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

var File_admin_service_v1_i_menu_proto protoreflect.FileDescriptor

var file_admin_service_v1_i_menu_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2f,
	0x76, 0x31, 0x2f, 0x69, 0x5f, 0x6d, 0x65, 0x6e, 0x75, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x10, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x76,
	0x31, 0x1a, 0x24, 0x67, 0x6e, 0x6f, 0x73, 0x74, 0x69, 0x63, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x61,
	0x70, 0x69, 0x2f, 0x76, 0x33, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x22, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x70, 0x61, 0x67, 0x69, 0x6e,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x70, 0x61, 0x67, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2f,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x65, 0x6e, 0x75, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x32, 0x9e, 0x04, 0x0a, 0x0b, 0x4d, 0x65, 0x6e, 0x75, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x63, 0x0a, 0x08, 0x4c, 0x69, 0x73, 0x74, 0x4d, 0x65, 0x6e,
	0x75, 0x12, 0x19, 0x2e, 0x70, 0x61, 0x67, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x50,
	0x61, 0x67, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x24, 0x2e, 0x63,
	0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x76,
	0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x4d, 0x65, 0x6e, 0x75, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x16, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x10, 0x12, 0x0e, 0x2f, 0x62, 0x6c, 0x6f,
	0x67, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x65, 0x6e, 0x75, 0x73, 0x12, 0x64, 0x0a, 0x07, 0x47, 0x65,
	0x74, 0x4d, 0x65, 0x6e, 0x75, 0x12, 0x22, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x4d, 0x65,
	0x6e, 0x75, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x18, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x65, 0x6e, 0x74, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x4d,
	0x65, 0x6e, 0x75, 0x22, 0x1b, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x15, 0x12, 0x13, 0x2f, 0x62, 0x6c,
	0x6f, 0x67, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x65, 0x6e, 0x75, 0x73, 0x2f, 0x7b, 0x69, 0x64, 0x7d,
	0x12, 0x68, 0x0a, 0x0a, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4d, 0x65, 0x6e, 0x75, 0x12, 0x25,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x2e, 0x76, 0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4d, 0x65, 0x6e, 0x75, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x18, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x65, 0x6e, 0x75, 0x22,
	0x19, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x13, 0x3a, 0x01, 0x2a, 0x22, 0x0e, 0x2f, 0x62, 0x6c, 0x6f,
	0x67, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x65, 0x6e, 0x75, 0x73, 0x12, 0x70, 0x0a, 0x0a, 0x55, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x4d, 0x65, 0x6e, 0x75, 0x12, 0x25, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x65,
	0x6e, 0x74, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x4d, 0x65, 0x6e, 0x75, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x18, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x65, 0x6e, 0x75, 0x22, 0x21, 0x82, 0xd3, 0xe4, 0x93, 0x02,
	0x1b, 0x3a, 0x04, 0x6d, 0x65, 0x6e, 0x75, 0x1a, 0x13, 0x2f, 0x62, 0x6c, 0x6f, 0x67, 0x2f, 0x76,
	0x31, 0x2f, 0x6d, 0x65, 0x6e, 0x75, 0x73, 0x2f, 0x7b, 0x69, 0x64, 0x7d, 0x12, 0x68, 0x0a, 0x0a,
	0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4d, 0x65, 0x6e, 0x75, 0x12, 0x25, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x65, 0x6e, 0x74, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x2e,
	0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4d, 0x65, 0x6e, 0x75, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x22, 0x1b, 0x82, 0xd3, 0xe4, 0x93, 0x02,
	0x15, 0x2a, 0x13, 0x2f, 0x62, 0x6c, 0x6f, 0x67, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x65, 0x6e, 0x75,
	0x73, 0x2f, 0x7b, 0x69, 0x64, 0x7d, 0x42, 0x58, 0x5a, 0x2a, 0x6b, 0x72, 0x61, 0x74, 0x6f, 0x73,
	0x2d, 0x62, 0x6c, 0x6f, 0x67, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x6f,
	0x2f, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2f, 0x76,
	0x31, 0x3b, 0x76, 0x31, 0xba, 0x47, 0x29, 0x12, 0x27, 0x0a, 0x12, 0xe8, 0x8f, 0x9c, 0xe5, 0x8d,
	0x95, 0xe7, 0xae, 0xa1, 0xe7, 0x90, 0x86, 0xe6, 0x8e, 0xa5, 0xe5, 0x8f, 0xa3, 0x12, 0x0c, 0xe8,
	0x8f, 0x9c, 0xe5, 0x8d, 0x95, 0xe7, 0xae, 0xa1, 0xe7, 0x90, 0x86, 0x32, 0x03, 0x31, 0x2e, 0x30,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var file_admin_service_v1_i_menu_proto_goTypes = []interface{}{
	(*pagination.PagingRequest)(nil), // 0: pagination.PagingRequest
	(*v1.GetMenuRequest)(nil),        // 1: content.service.v1.GetMenuRequest
	(*v1.CreateMenuRequest)(nil),     // 2: content.service.v1.CreateMenuRequest
	(*v1.UpdateMenuRequest)(nil),     // 3: content.service.v1.UpdateMenuRequest
	(*v1.DeleteMenuRequest)(nil),     // 4: content.service.v1.DeleteMenuRequest
	(*v1.ListMenuResponse)(nil),      // 5: content.service.v1.ListMenuResponse
	(*v1.Menu)(nil),                  // 6: content.service.v1.Menu
	(*emptypb.Empty)(nil),            // 7: google.protobuf.Empty
}
var file_admin_service_v1_i_menu_proto_depIdxs = []int32{
	0, // 0: admin.service.v1.MenuService.ListMenu:input_type -> pagination.PagingRequest
	1, // 1: admin.service.v1.MenuService.GetMenu:input_type -> content.service.v1.GetMenuRequest
	2, // 2: admin.service.v1.MenuService.CreateMenu:input_type -> content.service.v1.CreateMenuRequest
	3, // 3: admin.service.v1.MenuService.UpdateMenu:input_type -> content.service.v1.UpdateMenuRequest
	4, // 4: admin.service.v1.MenuService.DeleteMenu:input_type -> content.service.v1.DeleteMenuRequest
	5, // 5: admin.service.v1.MenuService.ListMenu:output_type -> content.service.v1.ListMenuResponse
	6, // 6: admin.service.v1.MenuService.GetMenu:output_type -> content.service.v1.Menu
	6, // 7: admin.service.v1.MenuService.CreateMenu:output_type -> content.service.v1.Menu
	6, // 8: admin.service.v1.MenuService.UpdateMenu:output_type -> content.service.v1.Menu
	7, // 9: admin.service.v1.MenuService.DeleteMenu:output_type -> google.protobuf.Empty
	5, // [5:10] is the sub-list for method output_type
	0, // [0:5] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_admin_service_v1_i_menu_proto_init() }
func file_admin_service_v1_i_menu_proto_init() {
	if File_admin_service_v1_i_menu_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_admin_service_v1_i_menu_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_admin_service_v1_i_menu_proto_goTypes,
		DependencyIndexes: file_admin_service_v1_i_menu_proto_depIdxs,
	}.Build()
	File_admin_service_v1_i_menu_proto = out.File
	file_admin_service_v1_i_menu_proto_rawDesc = nil
	file_admin_service_v1_i_menu_proto_goTypes = nil
	file_admin_service_v1_i_menu_proto_depIdxs = nil
}
