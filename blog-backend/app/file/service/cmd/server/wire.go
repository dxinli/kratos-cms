//go:build wireinject
// +build wireinject

// The build tag makes sure the stub is not built in the final build.

package main

import (
	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"

	"github.com/google/wire"

	"kratos-blog/app/file/service/internal/biz"
	"kratos-blog/app/file/service/internal/data"
	"kratos-blog/app/file/service/internal/server"
	"kratos-blog/app/file/service/internal/service"
	"kratos-blog/gen/api/go/common/conf"
)

// initApp init kratos application.
func initApp(*conf.Server, *conf.Registry, *conf.Data, *conf.Auth, log.Logger) (*kratos.App, func(), error) {
	panic(wire.Build(server.ProviderSet, data.ProviderSet, biz.ProviderSet, service.ProviderSet, newApp))
}
