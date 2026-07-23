{
  description = "frontdoor: Theater-native SNI-routing front door for colinrozzi.com";

  # packr 0.11.0 plain-build model (composition/fuse retired). frontdoor is a
  # plain cdylib built with `cargo build --target wasm32-unknown-unknown
  # --release` (the two link-args live in .cargo/config.toml). The resulting
  # frontdoor.wasm exports its own growable memory + __pack_alloc/__pack_free
  # and imports only host theater:simple/* — directly loadable, NO compose step.
  # The build no longer depends on the theater binary or binaryen; this devShell
  # only provides the rust toolchain + wasm-tools (for the import verify). See
  # theater docs/self-contained-actor-recipe.md (top block).

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          targets = [ "wasm32-unknown-unknown" ];
        };

      in {
        # Plain cargo build needs only cargo with the wasm32 target; wasm-tools
        # is here for the host-only-imports verify gate:
        #   nix develop --command cargo build --target wasm32-unknown-unknown --release
        #     -> target/wasm32-unknown-unknown/release/frontdoor.wasm
        devShells.default = pkgs.mkShell {
          packages = [
            rustToolchain
            pkgs.wasm-tools # validate + host-only import check
          ];
          # Echo to STDERR so `nix develop --command <cmd>` leaves stdout clean
          # (release CI captures `wasm-tools print` stdout to grep imports).
          shellHook = ''
            {
              echo "frontdoor dev environment (packr 0.11.0 plain build)"
              echo "  cargo build --target wasm32-unknown-unknown --release  # -> frontdoor.wasm"
            } >&2
          '';
        };
      });
}
