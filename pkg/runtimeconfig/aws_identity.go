// AWS workload identity supplies short-lived credentials to the production tunnel control plane.
package runtimeconfig

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/openai/openai-go/v3/auth"
)

type awsSubjectToken struct{}

func (awsSubjectToken) TokenType() auth.SubjectTokenType { return auth.SubjectTokenTypeJWT }

func (awsSubjectToken) GetToken(ctx context.Context, _ auth.HTTPDoer) (string, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return "", err
	}
	out, err := sts.NewFromConfig(cfg).GetWebIdentityToken(ctx, &sts.GetWebIdentityTokenInput{
		Audience:         []string{DefaultControlPlaneBaseURL + "/v1"},
		SigningAlgorithm: aws.String("RS256"),
		DurationSeconds:  aws.Int32(300),
	})
	if err != nil {
		return "", err
	}
	if aws.ToString(out.WebIdentityToken) == "" {
		return "", errors.New("STS returned an empty subject token")
	}
	return *out.WebIdentityToken, nil
}

func controlPlaneTokenProvider(apiKey, providerID, serviceAccountID string, baseURL *url.URL) (func(context.Context) (string, error), error) {
	if providerID == "" && serviceAccountID == "" {
		return nil, ValidateControlPlaneAPIKey(apiKey)
	}
	if apiKey != "" {
		return nil, errors.New("configure only one of an API key and AWS workload identity")
	}
	if strings.TrimSuffix(baseURL.String(), "/") != DefaultControlPlaneBaseURL {
		return nil, errors.New("AWS workload identity requires https://api.openai.com")
	}
	identity, err := auth.NewWorkloadIdentityAuth(auth.WorkloadIdentity{
		IdentityProviderID:   providerID,
		ServiceAccountID:     serviceAccountID,
		Provider:             awsSubjectToken{},
		RefreshBufferSeconds: 60,
	})
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(ctx context.Context) (string, error) {
		token, err := identity.GetToken(ctx, client)
		if err != nil {
			// SDK errors can include response bodies. Keep credentials out of tunnel logs.
			if oauthErr, ok := errors.AsType[*auth.OAuthError](err); ok {
				return "", fmt.Errorf("OpenAI workload token exchange failed (HTTP %d)", oauthErr.StatusCode)
			}
			return "", errors.New("AWS workload authentication failed")
		}
		return token, nil
	}, nil
}
