package resources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/seanpor/terraform-provider-ja4proxy/internal/client"
)

// New returns a provider constructor for use in resource tests.
func New(version string) func() fwprovider.Provider {
	return func() fwprovider.Provider {
		return &testProvider{version: version}
	}
}

type testProvider struct {
	version string
	client  *client.Client
}

func (p *testProvider) Metadata(_ context.Context, _ fwprovider.MetadataRequest, resp *fwprovider.MetadataResponse) {
	resp.TypeName = "ja4proxy"
	resp.Version = p.version
}

func (p *testProvider) Schema(_ context.Context, _ fwprovider.SchemaRequest, resp *fwprovider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"api_url": schema.StringAttribute{
				Required:    true,
				Description: "Base URL of the JA4proxy Management API.",
			},
			"api_token": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "Bearer token for authenticating with the Management API.",
			},
		},
	}
}

func (p *testProvider) Configure(ctx context.Context, req fwprovider.ConfigureRequest, resp *fwprovider.ConfigureResponse) {
	var config struct {
		APIURL   string `tfsdk:"api_url"`
		APIToken string `tfsdk:"api_token"`
	}
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.APIURL == "" {
		resp.Diagnostics.AddError("Missing api_url", "api_url is required")
		return
	}
	if config.APIToken == "" {
		resp.Diagnostics.AddError("Missing api_token", "api_token is required")
		return
	}

	c, err := client.New(config.APIURL, config.APIToken)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create client", err.Error())
		return
	}

	if _, err := c.Health(ctx); err != nil {
		resp.Diagnostics.AddError("Health check failed", err.Error())
		return
	}

	p.client = c
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *testProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewBanResource,
		NewAllowlistEntryResource,
		NewBlocklistEntryResource,
		NewWatchlistEntryResource,
		NewDialResource,
		NewWebhookResource,
	}
}

func (p *testProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

// NewProtocolV6 wraps the framework's NewProtocol6WithError for test compatibility.
// This is called by test files that reference "providerserver.NewProtocolV6" through
// this package (i.e., resources.NewProtocolV6).
func NewProtocolV6(p fwprovider.Provider) func() (tfprotov6.ProviderServer, error) {
	return providerserver.NewProtocol6WithError(p)
}
