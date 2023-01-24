package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/tx7do/kratos-blog/blog-backend/app/content/service/internal/biz"

	v1 "github.com/tx7do/kratos-blog/blog-backend/gen/api/go/content/service/v1"
	"github.com/tx7do/kratos-blog/blog-backend/gen/api/go/pagination"
)

type TagService struct {
	v1.UnimplementedTagServiceServer

	uc  *biz.TagUseCase
	log *log.Helper
}

func NewTagService(logger log.Logger, uc *biz.TagUseCase) *TagService {
	l := log.NewHelper(log.With(logger, "module", "tag/service/content-service"))
	return &TagService{
		log: l,
		uc:  uc,
	}
}

// ListTag 获取标签列表
func (s *TagService) ListTag(ctx context.Context, req *pagination.PagingRequest) (*v1.ListTagResponse, error) {
	return s.uc.List(ctx, req)
}

// GetTag 获取标签数据
func (s *TagService) GetTag(ctx context.Context, req *v1.GetTagRequest) (*v1.Tag, error) {
	return s.uc.Get(ctx, req)
}

// CreateTag 创建标签
func (s *TagService) CreateTag(ctx context.Context, req *v1.CreateTagRequest) (*v1.Tag, error) {
	return s.uc.Create(ctx, req)
}

// UpdateTag 更新标签
func (s *TagService) UpdateTag(ctx context.Context, req *v1.UpdateTagRequest) (*v1.Tag, error) {
	return s.uc.Update(ctx, req)
}

// DeleteTag 删除标签
func (s *TagService) DeleteTag(ctx context.Context, req *v1.DeleteTagRequest) (*emptypb.Empty, error) {
	_, err := s.uc.Delete(ctx, req)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
