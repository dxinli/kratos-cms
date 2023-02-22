// Code generated by protoc-gen-go-http. DO NOT EDIT.
// versions:
// - protoc-gen-go-http v2.5.3
// - protoc             (unknown)
// source: admin/service/v1/i_tag.proto

package v1

import (
	context "context"
	http "github.com/go-kratos/kratos/v2/transport/http"
	binding "github.com/go-kratos/kratos/v2/transport/http/binding"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	pagination "kratos-blog/gen/api/go/common/pagination"
	v1 "kratos-blog/gen/api/go/content/service/v1"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the kratos package it is being compiled against.
var _ = new(context.Context)
var _ = binding.EncodeURL

const _ = http.SupportPackageIsVersion1

const OperationTagServiceCreateTag = "/admin.service.v1.TagService/CreateTag"
const OperationTagServiceDeleteTag = "/admin.service.v1.TagService/DeleteTag"
const OperationTagServiceGetTag = "/admin.service.v1.TagService/GetTag"
const OperationTagServiceListTag = "/admin.service.v1.TagService/ListTag"
const OperationTagServiceUpdateTag = "/admin.service.v1.TagService/UpdateTag"

type TagServiceHTTPServer interface {
	CreateTag(context.Context, *v1.CreateTagRequest) (*v1.Tag, error)
	DeleteTag(context.Context, *v1.DeleteTagRequest) (*emptypb.Empty, error)
	GetTag(context.Context, *v1.GetTagRequest) (*v1.Tag, error)
	ListTag(context.Context, *pagination.PagingRequest) (*v1.ListTagResponse, error)
	UpdateTag(context.Context, *v1.UpdateTagRequest) (*v1.Tag, error)
}

func RegisterTagServiceHTTPServer(s *http.Server, srv TagServiceHTTPServer) {
	r := s.Route("/")
	r.GET("/blog/v1/tags", _TagService_ListTag0_HTTP_Handler(srv))
	r.GET("/blog/v1/tags/{id}", _TagService_GetTag0_HTTP_Handler(srv))
	r.POST("/blog/v1/tags", _TagService_CreateTag0_HTTP_Handler(srv))
	r.PUT("/blog/v1/tags/{id}", _TagService_UpdateTag0_HTTP_Handler(srv))
	r.DELETE("/blog/v1/tags/{id}", _TagService_DeleteTag0_HTTP_Handler(srv))
}

func _TagService_ListTag0_HTTP_Handler(srv TagServiceHTTPServer) func(ctx http.Context) error {
	return func(ctx http.Context) error {
		var in pagination.PagingRequest
		if err := ctx.BindQuery(&in); err != nil {
			return err
		}
		http.SetOperation(ctx, OperationTagServiceListTag)
		h := ctx.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.ListTag(ctx, req.(*pagination.PagingRequest))
		})
		out, err := h(ctx, &in)
		if err != nil {
			return err
		}
		reply := out.(*v1.ListTagResponse)
		return ctx.Result(200, reply)
	}
}

func _TagService_GetTag0_HTTP_Handler(srv TagServiceHTTPServer) func(ctx http.Context) error {
	return func(ctx http.Context) error {
		var in v1.GetTagRequest
		if err := ctx.BindQuery(&in); err != nil {
			return err
		}
		if err := ctx.BindVars(&in); err != nil {
			return err
		}
		http.SetOperation(ctx, OperationTagServiceGetTag)
		h := ctx.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.GetTag(ctx, req.(*v1.GetTagRequest))
		})
		out, err := h(ctx, &in)
		if err != nil {
			return err
		}
		reply := out.(*v1.Tag)
		return ctx.Result(200, reply)
	}
}

func _TagService_CreateTag0_HTTP_Handler(srv TagServiceHTTPServer) func(ctx http.Context) error {
	return func(ctx http.Context) error {
		var in v1.CreateTagRequest
		if err := ctx.Bind(&in); err != nil {
			return err
		}
		http.SetOperation(ctx, OperationTagServiceCreateTag)
		h := ctx.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.CreateTag(ctx, req.(*v1.CreateTagRequest))
		})
		out, err := h(ctx, &in)
		if err != nil {
			return err
		}
		reply := out.(*v1.Tag)
		return ctx.Result(200, reply)
	}
}

func _TagService_UpdateTag0_HTTP_Handler(srv TagServiceHTTPServer) func(ctx http.Context) error {
	return func(ctx http.Context) error {
		var in v1.UpdateTagRequest
		if err := ctx.Bind(&in.Tag); err != nil {
			return err
		}
		if err := ctx.BindQuery(&in); err != nil {
			return err
		}
		if err := ctx.BindVars(&in); err != nil {
			return err
		}
		http.SetOperation(ctx, OperationTagServiceUpdateTag)
		h := ctx.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.UpdateTag(ctx, req.(*v1.UpdateTagRequest))
		})
		out, err := h(ctx, &in)
		if err != nil {
			return err
		}
		reply := out.(*v1.Tag)
		return ctx.Result(200, reply)
	}
}

func _TagService_DeleteTag0_HTTP_Handler(srv TagServiceHTTPServer) func(ctx http.Context) error {
	return func(ctx http.Context) error {
		var in v1.DeleteTagRequest
		if err := ctx.BindQuery(&in); err != nil {
			return err
		}
		if err := ctx.BindVars(&in); err != nil {
			return err
		}
		http.SetOperation(ctx, OperationTagServiceDeleteTag)
		h := ctx.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.DeleteTag(ctx, req.(*v1.DeleteTagRequest))
		})
		out, err := h(ctx, &in)
		if err != nil {
			return err
		}
		reply := out.(*emptypb.Empty)
		return ctx.Result(200, reply)
	}
}

type TagServiceHTTPClient interface {
	CreateTag(ctx context.Context, req *v1.CreateTagRequest, opts ...http.CallOption) (rsp *v1.Tag, err error)
	DeleteTag(ctx context.Context, req *v1.DeleteTagRequest, opts ...http.CallOption) (rsp *emptypb.Empty, err error)
	GetTag(ctx context.Context, req *v1.GetTagRequest, opts ...http.CallOption) (rsp *v1.Tag, err error)
	ListTag(ctx context.Context, req *pagination.PagingRequest, opts ...http.CallOption) (rsp *v1.ListTagResponse, err error)
	UpdateTag(ctx context.Context, req *v1.UpdateTagRequest, opts ...http.CallOption) (rsp *v1.Tag, err error)
}

type TagServiceHTTPClientImpl struct {
	cc *http.Client
}

func NewTagServiceHTTPClient(client *http.Client) TagServiceHTTPClient {
	return &TagServiceHTTPClientImpl{client}
}

func (c *TagServiceHTTPClientImpl) CreateTag(ctx context.Context, in *v1.CreateTagRequest, opts ...http.CallOption) (*v1.Tag, error) {
	var out v1.Tag
	pattern := "/blog/v1/tags"
	path := binding.EncodeURL(pattern, in, false)
	opts = append(opts, http.Operation(OperationTagServiceCreateTag))
	opts = append(opts, http.PathTemplate(pattern))
	err := c.cc.Invoke(ctx, "POST", path, in, &out, opts...)
	if err != nil {
		return nil, err
	}
	return &out, err
}

func (c *TagServiceHTTPClientImpl) DeleteTag(ctx context.Context, in *v1.DeleteTagRequest, opts ...http.CallOption) (*emptypb.Empty, error) {
	var out emptypb.Empty
	pattern := "/blog/v1/tags/{id}"
	path := binding.EncodeURL(pattern, in, true)
	opts = append(opts, http.Operation(OperationTagServiceDeleteTag))
	opts = append(opts, http.PathTemplate(pattern))
	err := c.cc.Invoke(ctx, "DELETE", path, nil, &out, opts...)
	if err != nil {
		return nil, err
	}
	return &out, err
}

func (c *TagServiceHTTPClientImpl) GetTag(ctx context.Context, in *v1.GetTagRequest, opts ...http.CallOption) (*v1.Tag, error) {
	var out v1.Tag
	pattern := "/blog/v1/tags/{id}"
	path := binding.EncodeURL(pattern, in, true)
	opts = append(opts, http.Operation(OperationTagServiceGetTag))
	opts = append(opts, http.PathTemplate(pattern))
	err := c.cc.Invoke(ctx, "GET", path, nil, &out, opts...)
	if err != nil {
		return nil, err
	}
	return &out, err
}

func (c *TagServiceHTTPClientImpl) ListTag(ctx context.Context, in *pagination.PagingRequest, opts ...http.CallOption) (*v1.ListTagResponse, error) {
	var out v1.ListTagResponse
	pattern := "/blog/v1/tags"
	path := binding.EncodeURL(pattern, in, true)
	opts = append(opts, http.Operation(OperationTagServiceListTag))
	opts = append(opts, http.PathTemplate(pattern))
	err := c.cc.Invoke(ctx, "GET", path, nil, &out, opts...)
	if err != nil {
		return nil, err
	}
	return &out, err
}

func (c *TagServiceHTTPClientImpl) UpdateTag(ctx context.Context, in *v1.UpdateTagRequest, opts ...http.CallOption) (*v1.Tag, error) {
	var out v1.Tag
	pattern := "/blog/v1/tags/{id}"
	path := binding.EncodeURL(pattern, in, false)
	opts = append(opts, http.Operation(OperationTagServiceUpdateTag))
	opts = append(opts, http.PathTemplate(pattern))
	err := c.cc.Invoke(ctx, "PUT", path, in.Tag, &out, opts...)
	if err != nil {
		return nil, err
	}
	return &out, err
}
