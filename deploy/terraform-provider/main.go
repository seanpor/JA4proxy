package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/seanpor/terraform-provider-ja4proxy/internal/provider"
)

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run in debug mode with support for Delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/seanpor/ja4proxy",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New("dev"), opts)
	if err != nil {
		log.Fatal(err.Error())
	}
}
