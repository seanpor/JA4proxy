package resources

import (
	"context"
	"fmt"
	"sync"

	"github.com/anomalyco/terraform-provider-ja4proxy/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &dialResource{}
var _ resource.ResourceWithConfigure = &dialResource{}

// Singleton guard: tracks which provider instances already have a dial resource.
var (
	dialSingletonMu sync.Mutex
	dialSingletons  = make(map[string]bool) // key = provider base URL
)

type dialResource struct {
	client *client.Client
}

type dialResourceModel struct {
	ID    types.Int64 `tfsdk:"id"`
	Value types.Int64 `tfsdk:"value"`
}

func NewDialResource() resource.Resource {
	return &dialResource{}
}

func (r *dialResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dial"
}

func (r *dialResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage the global sensitivity dial setting (0-100). Only one instance is allowed.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Computed:    true,
				Description: "Internal resource ID (always 0).",
			},
			"value": schema.Int64Attribute{
				Required:    true,
				Description: "Dial sensitivity value (0-100). Changes are limited to a maximum delta of 10 per request.",
			},
		},
	}
}

func (r *dialResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *dialResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Singleton enforcement
	if err := r.checkSingleton(); err != nil {
		resp.Diagnostics.AddError("Dial singleton violation", err.Error())
		return
	}

	var plan dialResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	dialResp, err := r.client.UpdateDial(ctx, int(plan.Value.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Failed to set dial value", err.Error())
		dialSingletonMu.Lock()
		delete(dialSingletons, r.clientBaseURL())
		dialSingletonMu.Unlock()
		return
	}

	plan.ID = types.Int64Value(0)
	plan.Value = types.Int64Value(int64(dialResp.Value))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dialResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state dialResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	dialResp, err := r.client.GetDial(ctx)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.Int64Value(0)
	state.Value = types.Int64Value(int64(dialResp.Value))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dialResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan dialResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	dialResp, err := r.client.UpdateDial(ctx, int(plan.Value.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Failed to update dial value", err.Error())
		return
	}

	plan.ID = types.Int64Value(0)
	plan.Value = types.Int64Value(int64(dialResp.Value))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dialResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	dialSingletonMu.Lock()
	delete(dialSingletons, r.clientBaseURL())
	dialSingletonMu.Unlock()
	resp.State.RemoveResource(ctx)
}

func (r *dialResource) checkSingleton() error {
	dialSingletonMu.Lock()
	defer dialSingletonMu.Unlock()

	key := r.clientBaseURL()
	if dialSingletons[key] {
		return fmt.Errorf("only one ja4proxy_dial resource is allowed per provider instance (singleton violation)")
	}
	dialSingletons[key] = true
	return nil
}

func (r *dialResource) clientBaseURL() string {
	if r.client == nil {
		return ""
	}
	return r.client.BaseURL()
}
