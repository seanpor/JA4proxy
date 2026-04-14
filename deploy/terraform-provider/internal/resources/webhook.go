package resources

import (
	"context"
	"strings"

	"github.com/anomalyco/terraform-provider-ja4proxy/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &webhookResource{}
var _ resource.ResourceWithConfigure = &webhookResource{}
var _ resource.ResourceWithImportState = &webhookResource{}

type webhookResource struct {
	client *client.Client
}

type webhookResourceModel struct {
	ID        types.String `tfsdk:"id"`
	URL       types.String `tfsdk:"url"`
	Events    types.List   `tfsdk:"events"` // list of string
	Active    types.Bool   `tfsdk:"active"`
	Secret    types.String `tfsdk:"secret"`
	CreatedAt types.String `tfsdk:"created_at"`
	ManagedBy types.String `tfsdk:"managed_by"`
}

func NewWebhookResource() resource.Resource {
	return &webhookResource{}
}

func (r *webhookResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_webhook"
}

func (r *webhookResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage webhook notifications via the JA4proxy Management API.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Webhook identifier.",
			},
			"url": schema.StringAttribute{
				Required:    true,
				Description: "Webhook delivery URL.",
			},
			"events": schema.ListAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "List of event types to subscribe to.",
			},
			"active": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Whether the webhook is active (default: true).",
			},
			"secret": schema.StringAttribute{
				Computed:  true,
				Sensitive: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Webhook signing secret (returned only on creation).",
			},
			"created_at": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Timestamp when the webhook was created.",
			},
			"managed_by": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Management source.",
			},
		},
	}
}

func (r *webhookResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Type", "Expected *client.Client.")
		return
	}
	r.client = c
}

func (r *webhookResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan webhookResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var events []string
	resp.Diagnostics.Append(plan.Events.ElementsAs(ctx, &events, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	active := true
	if !plan.Active.IsNull() && !plan.Active.IsUnknown() {
		active = plan.Active.ValueBool()
	}

	webhookResp, err := r.client.CreateWebhook(ctx, plan.URL.ValueString(), events, active)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create webhook", err.Error())
		return
	}

	plan.ID = types.StringValue(webhookResp.ID)
	plan.Secret = types.StringValue(webhookResp.Secret)
	plan.CreatedAt = types.StringValue(webhookResp.CreatedAt)
	plan.ManagedBy = types.StringValue(webhookResp.ManagedBy)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *webhookResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state webhookResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	wh, err := r.client.GetWebhook(ctx, state.ID.ValueString())
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.URL = types.StringValue(wh.URL)
	evts, d := types.ListValueFrom(ctx, types.StringType, wh.Events)
	resp.Diagnostics.Append(d...)
	state.Events = evts
	state.Active = types.BoolValue(wh.Active)
	state.CreatedAt = types.StringValue(wh.CreatedAt)
	state.ManagedBy = types.StringValue(wh.ManagedBy)
	// Preserve secret from existing state — API does not return it on subsequent reads

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *webhookResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan webhookResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var events []string
	resp.Diagnostics.Append(plan.Events.ElementsAs(ctx, &events, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	active := plan.Active.ValueBool()

	wh, err := r.client.UpdateWebhook(ctx, plan.ID.ValueString(), plan.URL.ValueString(), events, active)
	if err != nil {
		resp.Diagnostics.AddError("Failed to update webhook", err.Error())
		return
	}

	plan.URL = types.StringValue(wh.URL)
	evts, diags := types.ListValueFrom(ctx, types.StringType, wh.Events)
	resp.Diagnostics.Append(diags...)
	plan.Events = evts
	plan.Active = types.BoolValue(wh.Active)
	plan.CreatedAt = types.StringValue(wh.CreatedAt)
	plan.ManagedBy = types.StringValue(wh.ManagedBy)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *webhookResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state webhookResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_ = r.client.DeleteWebhook(ctx, state.ID.ValueString())
	resp.State.RemoveResource(ctx)
}

func (r *webhookResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Webhook import ID must not be empty.")
		return
	}
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
