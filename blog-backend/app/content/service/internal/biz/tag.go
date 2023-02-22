package biz

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"

	"kratos-blog/gen/api/go/common/pagination"
	"kratos-blog/gen/api/go/content/service/v1"
)

type TagRepo interface {
	List(ctx context.Context, req *pagination.PagingRequest) (*v1.ListTagResponse, error)
	Get(ctx context.Context, req *v1.GetTagRequest) (*v1.Tag, error)
	Create(ctx context.Context, req *v1.CreateTagRequest) (*v1.Tag, error)
	Update(ctx context.Context, req *v1.UpdateTagRequest) (*v1.Tag, error)
	Delete(ctx context.Context, req *v1.DeleteTagRequest) (bool, error)
}

type TagUseCase struct {
	repo TagRepo
	log  *log.Helper
}

func NewTagUseCase(repo TagRepo, logger log.Logger) *TagUseCase {
	l := log.NewHelper(log.With(logger, "module", "tag/usecase/content-service"))
	return &TagUseCase{
		repo: repo,
		log:  l,
	}
}

func (uc *TagUseCase) List(ctx context.Context, req *pagination.PagingRequest) (*v1.ListTagResponse, error) {
	return uc.repo.List(ctx, req)
}

func (uc *TagUseCase) Get(ctx context.Context, req *v1.GetTagRequest) (*v1.Tag, error) {
	return uc.repo.Get(ctx, req)
}

func (uc *TagUseCase) Create(ctx context.Context, req *v1.CreateTagRequest) (*v1.Tag, error) {
	return uc.repo.Create(ctx, req)
}

func (uc *TagUseCase) Update(ctx context.Context, req *v1.UpdateTagRequest) (*v1.Tag, error) {
	return uc.repo.Update(ctx, req)
}

func (uc *TagUseCase) Delete(ctx context.Context, req *v1.DeleteTagRequest) (bool, error) {
	return uc.repo.Delete(ctx, req)
}
