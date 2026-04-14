package provider

import (
	"context"

	"github.com/anomalyco/terraform-provider-ja4proxy/internal/client"
	"github.com/anomalyco/terraform-provider-ja4proxy/internal/resources"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the provider.Provider interface.
var _ provider.Provider = &ja4proxyProvider{}

type ja4proxyProvider struct {
	version string
	client  *client.Client
}

type ja4proxyProviderModel struct {
	APIURL   types.String `tfsdk:"api_url"`
	APIToken types.String `tfsdk:"api_token"`
}

// New creates the provider instance.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &ja4proxyProvider{version: version}
	}
}

func (p *ja4proxyProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ja4proxy"
	resp.Version = p.version
}

func (p *ja4proxyProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Terraform provider for the JA4proxy Management API.",
		Attributes: map[string]schema.Attribute{
			"api_url": schema.StringAttribute{
				Required:    true,
				Description: "Base URL of the JA4proxy Management API (e.g. http://localhost:8090).",
			},
			"api_token": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "Bearer token for authenticating with the Management API.",
			},
		},
	}
}

func (p *ja4proxyProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config ja4proxyProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate required fields
	if config.APIURL.IsNull() || config.APIURL.IsUnknown() || config.APIURL.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing api_url",
			"The provider requires a valid api_url. Please set api_url in the provider configuration.",
		)
		return
	}
	if config.APIToken.IsNull() || config.APIToken.IsUnknown() || config.APIToken.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing api_token",
			"The provider requires a valid api_token. Please set api_token in the provider configuration.",
		)
		return
	}

	// Create client
	c, err := client.New(config.APIURL.ValueString(), config.APIToken.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to create API client", err.Error())
		return
	}

	// Health check
	if _, err := c.Health(ctx); err != nil {
		resp.Diagnostics.AddError(
			"Health check failed",
			"Unable to connect to the JA4proxy Management API at "+config.APIURL.ValueString()+": "+err.Error(),
		)
		return
	}

	p.client = c
	resp.DataSourceData = c
	resp.ResourceData = c
}

func (p *ja4proxyProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		resources.NewBanResource,
		resources.NewAllowlistEntryResource,
		resources.NewBlocklistEntryResource,
		resources.NewWatchlistEntryResource,
		resources.NewDialResource,
		resources.NewWebhookResource,
	}
}

func (p *ja4proxyProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
