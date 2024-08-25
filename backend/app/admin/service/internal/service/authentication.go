package service

import (
	"context"
	v1 "kratos-cms/api/gen/go/front/service/v1"

	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/protobuf/types/known/emptypb"

	adminV1 "kratos-cms/api/gen/go/admin/service/v1"
	userV1 "kratos-cms/api/gen/go/user/service/v1"

	"kratos-cms/pkg/cache"
	"kratos-cms/pkg/middleware/auth"
)

type AuthenticationService struct {
	v1.UnimplementedAuthenticationServiceServer

	uc   userV1.UserServiceClient
	utuc *cache.UserToken

	log *log.Helper
}

func NewAuthenticationService(logger log.Logger, uc userV1.UserServiceClient, utuc *cache.UserToken) *AuthenticationService {
	l := log.NewHelper(log.With(logger, "module", "user/service/admin-service"))
	return &AuthenticationService{
		log:  l,
		uc:   uc,
		utuc: utuc,
	}
}

// Register 注册
func (s *AuthenticationService) Register(ctx context.Context, req *adminV1.RegisterRequest) (*emptypb.Empty, error) {
	_, err := s.uc.CreateUser(ctx, &userV1.CreateUserRequest{
		User: &userV1.User{
			UserName: &req.Username,
			Password: &req.Password,
			Email:    &req.Email,
			NickName: &req.NickName,
		},
	})
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// Login 登陆
func (s *AuthenticationService) Login(ctx context.Context, req *adminV1.LoginRequest) (*adminV1.LoginResponse, error) {
	if _, err := s.uc.VerifyPassword(ctx, &userV1.VerifyPasswordRequest{
		UserName: req.GetUsername(),
		Password: req.GetPassword(),
	}); err != nil {
		return &adminV1.LoginResponse{}, err
	}

	user, err := s.uc.GetUserByUserName(ctx, &userV1.GetUserByUserNameRequest{UserName: req.GetUsername()})
	if err != nil {
		return &adminV1.LoginResponse{}, err
	}

	accessToken, refreshToken, err := s.utuc.GenerateToken(ctx, user)
	if err != nil {
		return nil, err
	}

	return &adminV1.LoginResponse{
		TokenType:    adminV1.TokenType_bearer.String(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// Logout 登出
func (s *AuthenticationService) Logout(ctx context.Context, req *adminV1.LogoutRequest) (*emptypb.Empty, error) {
	err := s.utuc.RemoveToken(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *AuthenticationService) GetMe(ctx context.Context, req *adminV1.GetMeRequest) (*userV1.User, error) {
	authInfo, err := auth.FromContext(ctx)
	if err != nil {
		s.log.Errorf("用户认证失败[%s]", err.Error())
		return nil, adminV1.ErrorAccessForbidden("用户认证失败")
	}

	req.Id = authInfo.UserId

	return s.uc.GetUser(ctx, &userV1.GetUserRequest{
		Id: req.GetId(),
	})
}
