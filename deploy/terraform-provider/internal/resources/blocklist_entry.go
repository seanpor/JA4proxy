package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/seanpor/terraform-provider-ja4proxy/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
)

var _ resource.Resource = &blocklistEntryResource{}
var _ resource.ResourceWithConfigure = &blocklistEntryResource{}
var _ resource.ResourceWithImportState = &blocklistEntryResource{}

type blocklistEntryResource struct {
	client *client.Client
}

func NewBlocklistEntryResource() resource.Resource {
	return &blocklistEntryResource{}
}

func (r *blocklistEntryResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_blocklist_entry"
}

func (r *blocklistEntryResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage blocklist entries via the JA4proxy Management API.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Unique entry identifier.",
			},
			"entry": schema.StringAttribute{
				Required:    true,
				Description: "The entry value (e.g. JARM fingerprint, IP, CIDR).",
			},
			"managed_by": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Owner tag (default: terraform).",
			},
			"note": schema.StringAttribute{
				Optional:    true,
				Description: "Human-readable note about this entry.",
			},
			"list_type": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "List type (blocklist).",
			},
			"created_at": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Timestamp when the entry was created.",
			},
			"created_by": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Who created the entry.",
			},
			"expires_at": schema.StringAttribute{
				Optional:    true,
				Description: "Optional expiry timestamp (RFC3339).",
			},
		},
	}
}

func (r *blocklistEntryResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *blocklistEntryResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan listEntryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	managedBy := "terraform"
	if !plan.ManagedBy.IsNull() && plan.ManagedBy.ValueString() != "" {
		managedBy = plan.ManagedBy.ValueString()
	}

	var expiresAt *string
	if !plan.ExpiresAt.IsNull() && plan.ExpiresAt.ValueString() != "" {
		e := plan.ExpiresAt.ValueString()
		expiresAt = &e
	}

	entry, err := r.client.CreateListEntry(ctx, "blocklist", plan.Entry.ValueString(), managedBy, plan.Note.ValueString(), expiresAt)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create blocklist entry", err.Error())
		return
	}

	populateListModel(&plan, entry)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *blocklistEntryResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state listEntryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	entry, err := r.client.GetListEntryByID(ctx, "blocklist", state.ID.ValueString())
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	populateListModel(&state, entry)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *blocklistEntryResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan listEntryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state listEntryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_ = r.client.DeleteListEntry(ctx, "blocklist", state.ID.ValueString())

	managedBy := "terraform"
	if !plan.ManagedBy.IsNull() && plan.ManagedBy.ValueString() != "" {
		managedBy = plan.ManagedBy.ValueString()
	}

	var expiresAt *string
	if !plan.ExpiresAt.IsNull() && plan.ExpiresAt.ValueString() != "" {
		e := plan.ExpiresAt.ValueString()
		expiresAt = &e
	}

	entry, err := r.client.CreateListEntry(ctx, "blocklist", plan.Entry.ValueString(), managedBy, plan.Note.ValueString(), expiresAt)
	if err != nil {
		resp.Diagnostics.AddError("Failed to update blocklist entry", err.Error())
		return
	}

	populateListModel(&plan, entry)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *blocklistEntryResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state listEntryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_ = r.client.DeleteListEntry(ctx, "blocklist", state.ID.ValueString())
	resp.State.RemoveResource(ctx)
}

func (r *blocklistEntryResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, "/", 2)
	if len(parts) != 2 {
		resp.Diagnostics.AddError(
			"Invalid import ID format",
			fmt.Sprintf("Expected 'blocklist/<id>', got %q", req.ID),
		)
		return
	}
	if parts[0] != "blocklist" {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Expected list type 'blocklist', got %q", parts[0]),
		)
		return
	}
	req.ID = parts[1]
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
