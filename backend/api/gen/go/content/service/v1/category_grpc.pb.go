// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             (unknown)
// source: content/service/v1/category.proto

package servicev1

import (
	context "context"
	v1 "github.com/tx7do/kratos-bootstrap/api/gen/go/pagination/v1"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	CategoryService_ListCategory_FullMethodName   = "/content.service.v1.CategoryService/ListCategory"
	CategoryService_GetCategory_FullMethodName    = "/content.service.v1.CategoryService/GetCategory"
	CategoryService_CreateCategory_FullMethodName = "/content.service.v1.CategoryService/CreateCategory"
	CategoryService_UpdateCategory_FullMethodName = "/content.service.v1.CategoryService/UpdateCategory"
	CategoryService_DeleteCategory_FullMethodName = "/content.service.v1.CategoryService/DeleteCategory"
)

// CategoryServiceClient is the client API for CategoryService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// 类别服务
type CategoryServiceClient interface {
	// 获取类别列表
	ListCategory(ctx context.Context, in *v1.PagingRequest, opts ...grpc.CallOption) (*ListCategoryResponse, error)
	// 获取类别数据
	GetCategory(ctx context.Context, in *GetCategoryRequest, opts ...grpc.CallOption) (*Category, error)
	// 创建类别
	CreateCategory(ctx context.Context, in *CreateCategoryRequest, opts ...grpc.CallOption) (*Category, error)
	// 更新类别
	UpdateCategory(ctx context.Context, in *UpdateCategoryRequest, opts ...grpc.CallOption) (*Category, error)
	// 删除类别
	DeleteCategory(ctx context.Context, in *DeleteCategoryRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type categoryServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewCategoryServiceClient(cc grpc.ClientConnInterface) CategoryServiceClient {
	return &categoryServiceClient{cc}
}

func (c *categoryServiceClient) ListCategory(ctx context.Context, in *v1.PagingRequest, opts ...grpc.CallOption) (*ListCategoryResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListCategoryResponse)
	err := c.cc.Invoke(ctx, CategoryService_ListCategory_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *categoryServiceClient) GetCategory(ctx context.Context, in *GetCategoryRequest, opts ...grpc.CallOption) (*Category, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Category)
	err := c.cc.Invoke(ctx, CategoryService_GetCategory_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *categoryServiceClient) CreateCategory(ctx context.Context, in *CreateCategoryRequest, opts ...grpc.CallOption) (*Category, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Category)
	err := c.cc.Invoke(ctx, CategoryService_CreateCategory_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *categoryServiceClient) UpdateCategory(ctx context.Context, in *UpdateCategoryRequest, opts ...grpc.CallOption) (*Category, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Category)
	err := c.cc.Invoke(ctx, CategoryService_UpdateCategory_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *categoryServiceClient) DeleteCategory(ctx context.Context, in *DeleteCategoryRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, CategoryService_DeleteCategory_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CategoryServiceServer is the server API for CategoryService service.
// All implementations must embed UnimplementedCategoryServiceServer
// for forward compatibility.
//
// 类别服务
type CategoryServiceServer interface {
	// 获取类别列表
	ListCategory(context.Context, *v1.PagingRequest) (*ListCategoryResponse, error)
	// 获取类别数据
	GetCategory(context.Context, *GetCategoryRequest) (*Category, error)
	// 创建类别
	CreateCategory(context.Context, *CreateCategoryRequest) (*Category, error)
	// 更新类别
	UpdateCategory(context.Context, *UpdateCategoryRequest) (*Category, error)
	// 删除类别
	DeleteCategory(context.Context, *DeleteCategoryRequest) (*emptypb.Empty, error)
	mustEmbedUnimplementedCategoryServiceServer()
}

// UnimplementedCategoryServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedCategoryServiceServer struct{}

func (UnimplementedCategoryServiceServer) ListCategory(context.Context, *v1.PagingRequest) (*ListCategoryResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListCategory not implemented")
}
func (UnimplementedCategoryServiceServer) GetCategory(context.Context, *GetCategoryRequest) (*Category, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCategory not implemented")
}
func (UnimplementedCategoryServiceServer) CreateCategory(context.Context, *CreateCategoryRequest) (*Category, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateCategory not implemented")
}
func (UnimplementedCategoryServiceServer) UpdateCategory(context.Context, *UpdateCategoryRequest) (*Category, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateCategory not implemented")
}
func (UnimplementedCategoryServiceServer) DeleteCategory(context.Context, *DeleteCategoryRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteCategory not implemented")
}
func (UnimplementedCategoryServiceServer) mustEmbedUnimplementedCategoryServiceServer() {}
func (UnimplementedCategoryServiceServer) testEmbeddedByValue()                         {}

// UnsafeCategoryServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CategoryServiceServer will
// result in compilation errors.
type UnsafeCategoryServiceServer interface {
	mustEmbedUnimplementedCategoryServiceServer()
}

func RegisterCategoryServiceServer(s grpc.ServiceRegistrar, srv CategoryServiceServer) {
	// If the following call pancis, it indicates UnimplementedCategoryServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&CategoryService_ServiceDesc, srv)
}

func _CategoryService_ListCategory_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(v1.PagingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CategoryServiceServer).ListCategory(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CategoryService_ListCategory_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CategoryServiceServer).ListCategory(ctx, req.(*v1.PagingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CategoryService_GetCategory_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetCategoryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CategoryServiceServer).GetCategory(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CategoryService_GetCategory_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CategoryServiceServer).GetCategory(ctx, req.(*GetCategoryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CategoryService_CreateCategory_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateCategoryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CategoryServiceServer).CreateCategory(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CategoryService_CreateCategory_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CategoryServiceServer).CreateCategory(ctx, req.(*CreateCategoryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CategoryService_UpdateCategory_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateCategoryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CategoryServiceServer).UpdateCategory(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CategoryService_UpdateCategory_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CategoryServiceServer).UpdateCategory(ctx, req.(*UpdateCategoryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CategoryService_DeleteCategory_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteCategoryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CategoryServiceServer).DeleteCategory(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CategoryService_DeleteCategory_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CategoryServiceServer).DeleteCategory(ctx, req.(*DeleteCategoryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// CategoryService_ServiceDesc is the grpc.ServiceDesc for CategoryService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CategoryService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "content.service.v1.CategoryService",
	HandlerType: (*CategoryServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListCategory",
			Handler:    _CategoryService_ListCategory_Handler,
		},
		{
			MethodName: "GetCategory",
			Handler:    _CategoryService_GetCategory_Handler,
		},
		{
			MethodName: "CreateCategory",
			Handler:    _CategoryService_CreateCategory_Handler,
		},
		{
			MethodName: "UpdateCategory",
			Handler:    _CategoryService_UpdateCategory_Handler,
		},
		{
			MethodName: "DeleteCategory",
			Handler:    _CategoryService_DeleteCategory_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "content/service/v1/category.proto",
}
