// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: admin/service/v1/i_link.proto

package servicev1

import (
	context "context"
	v1 "github.com/tx7do/kratos-bootstrap/api/gen/go/pagination/v1"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	v11 "kratos-cms/gen/api/go/content/service/v1"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	LinkService_ListLink_FullMethodName   = "/admin.service.v1.LinkService/ListLink"
	LinkService_GetLink_FullMethodName    = "/admin.service.v1.LinkService/GetLink"
	LinkService_CreateLink_FullMethodName = "/admin.service.v1.LinkService/CreateLink"
	LinkService_UpdateLink_FullMethodName = "/admin.service.v1.LinkService/UpdateLink"
	LinkService_DeleteLink_FullMethodName = "/admin.service.v1.LinkService/DeleteLink"
)

// LinkServiceClient is the client API for LinkService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type LinkServiceClient interface {
	// 获取链接列表
	ListLink(ctx context.Context, in *v1.PagingRequest, opts ...grpc.CallOption) (*v11.ListLinkResponse, error)
	// 获取链接数据
	GetLink(ctx context.Context, in *v11.GetLinkRequest, opts ...grpc.CallOption) (*v11.Link, error)
	// 创建链接
	CreateLink(ctx context.Context, in *v11.CreateLinkRequest, opts ...grpc.CallOption) (*v11.Link, error)
	// 更新链接
	UpdateLink(ctx context.Context, in *v11.UpdateLinkRequest, opts ...grpc.CallOption) (*v11.Link, error)
	// 删除链接
	DeleteLink(ctx context.Context, in *v11.DeleteLinkRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type linkServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewLinkServiceClient(cc grpc.ClientConnInterface) LinkServiceClient {
	return &linkServiceClient{cc}
}

func (c *linkServiceClient) ListLink(ctx context.Context, in *v1.PagingRequest, opts ...grpc.CallOption) (*v11.ListLinkResponse, error) {
	out := new(v11.ListLinkResponse)
	err := c.cc.Invoke(ctx, LinkService_ListLink_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *linkServiceClient) GetLink(ctx context.Context, in *v11.GetLinkRequest, opts ...grpc.CallOption) (*v11.Link, error) {
	out := new(v11.Link)
	err := c.cc.Invoke(ctx, LinkService_GetLink_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *linkServiceClient) CreateLink(ctx context.Context, in *v11.CreateLinkRequest, opts ...grpc.CallOption) (*v11.Link, error) {
	out := new(v11.Link)
	err := c.cc.Invoke(ctx, LinkService_CreateLink_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *linkServiceClient) UpdateLink(ctx context.Context, in *v11.UpdateLinkRequest, opts ...grpc.CallOption) (*v11.Link, error) {
	out := new(v11.Link)
	err := c.cc.Invoke(ctx, LinkService_UpdateLink_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *linkServiceClient) DeleteLink(ctx context.Context, in *v11.DeleteLinkRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, LinkService_DeleteLink_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LinkServiceServer is the server API for LinkService service.
// All implementations must embed UnimplementedLinkServiceServer
// for forward compatibility
type LinkServiceServer interface {
	// 获取链接列表
	ListLink(context.Context, *v1.PagingRequest) (*v11.ListLinkResponse, error)
	// 获取链接数据
	GetLink(context.Context, *v11.GetLinkRequest) (*v11.Link, error)
	// 创建链接
	CreateLink(context.Context, *v11.CreateLinkRequest) (*v11.Link, error)
	// 更新链接
	UpdateLink(context.Context, *v11.UpdateLinkRequest) (*v11.Link, error)
	// 删除链接
	DeleteLink(context.Context, *v11.DeleteLinkRequest) (*emptypb.Empty, error)
	mustEmbedUnimplementedLinkServiceServer()
}

// UnimplementedLinkServiceServer must be embedded to have forward compatible implementations.
type UnimplementedLinkServiceServer struct {
}

func (UnimplementedLinkServiceServer) ListLink(context.Context, *v1.PagingRequest) (*v11.ListLinkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListLink not implemented")
}
func (UnimplementedLinkServiceServer) GetLink(context.Context, *v11.GetLinkRequest) (*v11.Link, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetLink not implemented")
}
func (UnimplementedLinkServiceServer) CreateLink(context.Context, *v11.CreateLinkRequest) (*v11.Link, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateLink not implemented")
}
func (UnimplementedLinkServiceServer) UpdateLink(context.Context, *v11.UpdateLinkRequest) (*v11.Link, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateLink not implemented")
}
func (UnimplementedLinkServiceServer) DeleteLink(context.Context, *v11.DeleteLinkRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteLink not implemented")
}
func (UnimplementedLinkServiceServer) mustEmbedUnimplementedLinkServiceServer() {}

// UnsafeLinkServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to LinkServiceServer will
// result in compilation errors.
type UnsafeLinkServiceServer interface {
	mustEmbedUnimplementedLinkServiceServer()
}

func RegisterLinkServiceServer(s grpc.ServiceRegistrar, srv LinkServiceServer) {
	s.RegisterService(&LinkService_ServiceDesc, srv)
}

func _LinkService_ListLink_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(v1.PagingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LinkServiceServer).ListLink(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: LinkService_ListLink_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LinkServiceServer).ListLink(ctx, req.(*v1.PagingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _LinkService_GetLink_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(v11.GetLinkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LinkServiceServer).GetLink(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: LinkService_GetLink_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LinkServiceServer).GetLink(ctx, req.(*v11.GetLinkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _LinkService_CreateLink_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(v11.CreateLinkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LinkServiceServer).CreateLink(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: LinkService_CreateLink_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LinkServiceServer).CreateLink(ctx, req.(*v11.CreateLinkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _LinkService_UpdateLink_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(v11.UpdateLinkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LinkServiceServer).UpdateLink(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: LinkService_UpdateLink_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LinkServiceServer).UpdateLink(ctx, req.(*v11.UpdateLinkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _LinkService_DeleteLink_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(v11.DeleteLinkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LinkServiceServer).DeleteLink(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: LinkService_DeleteLink_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LinkServiceServer).DeleteLink(ctx, req.(*v11.DeleteLinkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// LinkService_ServiceDesc is the grpc.ServiceDesc for LinkService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var LinkService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "admin.service.v1.LinkService",
	HandlerType: (*LinkServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListLink",
			Handler:    _LinkService_ListLink_Handler,
		},
		{
			MethodName: "GetLink",
			Handler:    _LinkService_GetLink_Handler,
		},
		{
			MethodName: "CreateLink",
			Handler:    _LinkService_CreateLink_Handler,
		},
		{
			MethodName: "UpdateLink",
			Handler:    _LinkService_UpdateLink_Handler,
		},
		{
			MethodName: "DeleteLink",
			Handler:    _LinkService_DeleteLink_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "admin/service/v1/i_link.proto",
}
