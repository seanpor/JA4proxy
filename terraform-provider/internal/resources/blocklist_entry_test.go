package resources

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// ── Test: Create, Read, Delete blocklist_entry ───────────────────────────────

func TestBlocklistEntry_CreateReadDelete(t *testing.T) {
	store := newMockListStore()
	server := newListMockServer(store)
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ja4proxy": func() (tfprotov6.ProviderServer, error) {
				return providerServer, nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_blocklist_entry" "test" {
						entry      = "jarm:malicious-fingerprint"
						managed_by = "terraform"
						note       = "Known malicious JARM signature"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_blocklist_entry.test", "entry", "jarm:malicious-fingerprint"),
					resource.TestCheckResourceAttr("ja4proxy_blocklist_entry.test", "managed_by", "terraform"),
					resource.TestCheckResourceAttr("ja4proxy_blocklist_entry.test", "note", "Known malicious JARM signature"),
					resource.TestCheckResourceAttrSet("ja4proxy_blocklist_entry.test", "id"),
					resource.TestCheckResourceAttrSet("ja4proxy_blocklist_entry.test", "created_at"),
				),
			},
			{
				Config:  fmt.Sprintf(`provider "ja4proxy" {
    api_url   = %q
    api_token = "test-token"
  }`, server.URL),
				Destroy: true,
			},
		},
	})
}

// ── Test: blocklist_entry with IP/CIDR entry ─────────────────────────────────

func TestBlocklistEntry_IPCIDR(t *testing.T) {
	store := newMockListStore()
	server := newListMockServer(store)
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ja4proxy": func() (tfprotov6.ProviderServer, error) {
				return providerServer, nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_blocklist_entry" "cidr" {
						entry      = "jarm:scanner-signature"
						managed_by = "terraform"
						note       = "Scanner network block"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_blocklist_entry.cidr", "entry", "jarm:scanner-signature"),
				),
			},
		},
	})
}

// ── Test: blocklist_entry import ──────────────────────────────────────────────

func TestBlocklistEntry_Import(t *testing.T) {
	store := newMockListStore()
	store.create("blocklist", "jarm:import-block", "terraform", "pre-existing block", nil)

	server := newListMockServer(store)
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	entry := store.list("blocklist")[0]
	importID := entry["id"].(string)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ja4proxy": func() (tfprotov6.ProviderServer, error) {
				return providerServer, nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_blocklist_entry" "imported" {
						entry = "PLACEHOLDER"
					}
				`, server.URL),
			},
			{
				ResourceName:                         "ja4proxy_blocklist_entry.imported",
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("blocklist/%s", importID),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
			},
		},
	})
}

// ── Test: blocklist_entry idempotent ──────────────────────────────────────────

func TestBlocklistEntry_Idempotent(t *testing.T) {
	store := newMockListStore()
	server := newListMockServer(store)
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ja4proxy": func() (tfprotov6.ProviderServer, error) {
				return providerServer, nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_blocklist_entry" "dup" {
						entry      = "jarm:block-dup"
						managed_by = "terraform"
						note       = "blocklist dupe test"
					}
				`, server.URL),
			},
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_blocklist_entry" "dup" {
						entry      = "jarm:block-dup"
						managed_by = "terraform"
						note       = "blocklist dupe test"
					}
				`, server.URL),
				PlanOnly: true,
			},
		},
	})
}
