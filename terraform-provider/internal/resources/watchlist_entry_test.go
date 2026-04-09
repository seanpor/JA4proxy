package resources

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// ── Test: Create, Read, Delete watchlist_entry ───────────────────────────────

func TestWatchlistEntry_CreateReadDelete(t *testing.T) {
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
					resource "ja4proxy_watchlist_entry" "test" {
						entry      = "jarm:suspicious-but-not-blocked"
						managed_by = "terraform"
						note       = "Monitor this fingerprint"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_watchlist_entry.test", "entry", "jarm:suspicious-but-not-blocked"),
					resource.TestCheckResourceAttr("ja4proxy_watchlist_entry.test", "managed_by", "terraform"),
					resource.TestCheckResourceAttr("ja4proxy_watchlist_entry.test", "note", "Monitor this fingerprint"),
					resource.TestCheckResourceAttrSet("ja4proxy_watchlist_entry.test", "id"),
					resource.TestCheckResourceAttrSet("ja4proxy_watchlist_entry.test", "created_at"),
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

// ── Test: watchlist_entry with expires_at ────────────────────────────────────

func TestWatchlistEntry_WithExpiresAt(t *testing.T) {
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
					resource "ja4proxy_watchlist_entry" "expiring" {
						entry      = "jarm:temp-watch"
						managed_by = "terraform"
						note       = "Temporary watch during investigation"
						expires_at = "2027-06-30T00:00:00Z"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ja4proxy_watchlist_entry.expiring", "entry", "jarm:temp-watch"),
					resource.TestCheckResourceAttr("ja4proxy_watchlist_entry.expiring", "expires_at", "2027-06-30T00:00:00Z"),
				),
			},
		},
	})
}

// ── Test: watchlist_entry import ──────────────────────────────────────────────

func TestWatchlistEntry_Import(t *testing.T) {
	store := newMockListStore()
	store.create("watchlist", "jarm:import-watch", "terraform", "pre-existing watch", nil)

	server := newListMockServer(store)
	defer server.Close()

	providerServer := newListTestProvider(t, server.URL)

	entry := store.list("watchlist")[0]
	importID := entry["id"].(string)
	entryValue := entry["entry"].(string)

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
					resource "ja4proxy_watchlist_entry" "imported" {
						entry = %q
						note  = "pre-existing watch"
					}
				`, server.URL, entryValue),
			},
			{
				ResourceName:                         "ja4proxy_watchlist_entry.imported",
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("watchlist/%s", importID),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
			},
		},
	})
}

// ── Test: watchlist_entry idempotent ──────────────────────────────────────────

func TestWatchlistEntry_Idempotent(t *testing.T) {
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
					resource "ja4proxy_watchlist_entry" "dup" {
						entry      = "jarm:watch-dup"
						managed_by = "terraform"
						note       = "watchlist dupe test"
					}
				`, server.URL),
			},
			{
				Config: fmt.Sprintf(`
					provider "ja4proxy" {
						api_url   = %q
						api_token = "test-token"
					}
					resource "ja4proxy_watchlist_entry" "dup" {
						entry      = "jarm:watch-dup"
						managed_by = "terraform"
						note       = "watchlist dupe test"
					}
				`, server.URL),
				PlanOnly: true,
			},
		},
	})
}
