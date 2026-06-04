package resources

import (
	"context"

	"github.com/seanpor/terraform-provider-ja4proxy/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &banResource{}
var _ resource.ResourceWithConfigure = &banResource{}

type banResource struct {
	client *client.Client
}

type banResourceModel struct {
	ID     types.String `tfsdk:"id"`
	IP     types.String `tfsdk:"ip"`
	TTL    types.Int64  `tfsdk:"ttl"`
	Reason types.String `tfsdk:"reason"`
}

func NewBanResource() resource.Resource {
	return &banResource{}
}

func (r *banResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ban"
}

func (r *banResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage IP and CIDR bans via the JA4proxy Management API.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier (URL-encoded IP or CIDR).",
			},
			"ip": schema.StringAttribute{
				Required:    true,
				Description: "IP address or CIDR to ban (e.g. 10.0.0.1 or 198.51.100.0/24).",
			},
			"ttl": schema.Int64Attribute{
				Required:    true,
				Description: "Ban time-to-live in seconds.",
			},
			"reason": schema.StringAttribute{
				Required:    true,
				Description: "Reason for the ban.",
			},
		},
	}
}

func (r *banResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Type",
			"Expected *client.Client.",
		)
		return
	}
	r.client = c
}

func (r *banResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan banResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.CreateBan(ctx, plan.IP.ValueString(), int(plan.TTL.ValueInt64()), plan.Reason.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to create ban", err.Error())
		return
	}

	plan.ID = types.StringValue(plan.IP.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *banResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state banResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	bansResp, err := r.client.ListBans(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Failed to list bans", err.Error())
		return
	}

	// Find matching ban by IP
	var found bool
	for _, b := range bansResp.Bans {
		if b.IP == state.IP.ValueString() {
			found = true
			state.Reason = types.StringValue(b.Reason)
			if b.TTLRemaining != nil {
				state.TTL = types.Int64Value(int64(*b.TTLRemaining))
			}
			break
		}
	}

	if !found {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *banResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan banResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Re-POST to refresh TTL
	_, err := r.client.CreateBan(ctx, plan.IP.ValueString(), int(plan.TTL.ValueInt64()), plan.Reason.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to update ban", err.Error())
		return
	}

	plan.ID = types.StringValue(plan.IP.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *banResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state banResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.DeleteBan(ctx, state.IP.ValueString())
	if err != nil {
		// If the ban is already gone, treat deletion as successful
		state.IP.ValueString()
		_ = err // non-fatal if already removed
	}

	resp.State.RemoveResource(ctx)
}
