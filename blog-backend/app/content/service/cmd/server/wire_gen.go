// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package main

import (
	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-blog/blog-backend/app/content/service/internal/biz"
	"github.com/tx7do/kratos-blog/blog-backend/app/content/service/internal/conf"
	"github.com/tx7do/kratos-blog/blog-backend/app/content/service/internal/data"
	"github.com/tx7do/kratos-blog/blog-backend/app/content/service/internal/server"
	"github.com/tx7do/kratos-blog/blog-backend/app/content/service/internal/service"
)

// Injectors from wire.go:

// initApp init kratos application.
func initApp(confServer *conf.Server, registry *conf.Registry, confData *conf.Data, auth *conf.Auth, logger log.Logger) (*kratos.App, func(), error) {
	client := data.NewEntClient(confData, logger)
	redisClient := data.NewRedisClient(confData, logger)
	dataData, cleanup, err := data.NewData(client, redisClient, logger)
	if err != nil {
		return nil, nil, err
	}
	postRepo := data.NewPostRepo(dataData, logger)
	postUseCase := biz.NewPostUseCase(postRepo, logger)
	postService := service.NewPostService(logger, postUseCase)
	linkRepo := data.NewLinkRepo(dataData, logger)
	linkUseCase := biz.NewLinkUseCase(linkRepo, logger)
	linkService := service.NewLinkService(logger, linkUseCase)
	categoryRepo := data.NewCategoryRepo(dataData, logger)
	categoryUseCase := biz.NewCategoryUseCase(categoryRepo, logger)
	categoryService := service.NewCategoryService(logger, categoryUseCase)
	tagRepo := data.NewTagRepo(dataData, logger)
	tagUseCase := biz.NewTagUseCase(tagRepo, logger)
	tagService := service.NewTagService(logger, tagUseCase)
	grpcServer := server.NewGRPCServer(confServer, logger, postService, linkService, categoryService, tagService)
	registrar := server.NewRegistrar(registry)
	app := newApp(logger, grpcServer, registrar)
	return app, func() {
		cleanup()
	}, nil
}
