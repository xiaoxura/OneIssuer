package oidc

import (
	"sort"

	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/ory/fosite"
)

// fositeClientAdapter is intentionally confined to internal/oidc. Secret
// authentication is completed by client.Service before this view is created,
// so GetHashedSecret never exposes OneIssuer's digest to Fosite.
type fositeClientAdapter struct {
	value clientdomain.Client
}

var _ fosite.Client = (*fositeClientAdapter)(nil)

func newFositeClient(value clientdomain.Client) fosite.Client {
	return &fositeClientAdapter{value: value}
}

func (c *fositeClientAdapter) GetID() string                 { return c.value.ClientID }
func (c *fositeClientAdapter) GetHashedSecret() []byte       { return nil }
func (c *fositeClientAdapter) IsPublic() bool                { return c.value.Type == clientdomain.TypePublic }
func (c *fositeClientAdapter) GetAudience() fosite.Arguments { return fosite.Arguments{} }

func (c *fositeClientAdapter) GetRedirectURIs() []string {
	return append([]string(nil), c.value.RedirectURIs...)
}

func (c *fositeClientAdapter) GetGrantTypes() fosite.Arguments {
	return fosite.Arguments{"authorization_code"}
}

func (c *fositeClientAdapter) GetResponseTypes() fosite.Arguments {
	return fosite.Arguments{"code"}
}

func (c *fositeClientAdapter) GetScopes() fosite.Arguments {
	result := make([]string, 0, 3)
	for _, scope := range c.value.Scopes {
		if scope == "openid" || scope == "profile" || scope == "email" {
			result = append(result, scope)
		}
	}
	sort.Strings(result)
	return fosite.Arguments(result)
}
