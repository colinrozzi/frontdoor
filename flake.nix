{
  description = "frontdoor: Theater-native SNI-routing front door for colinrozzi.com";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";

    theater = {
      url = "github:colinrozzi/theater";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-overlay.follows = "rust-overlay";
      inputs.crane.follows = "crane";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane, theater }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          targets = [ "wasm32-unknown-unknown" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            (pkgs.lib.hasSuffix ".rs" path) ||
            (pkgs.lib.hasSuffix ".toml" path) ||
            (pkgs.lib.hasSuffix ".lock" path) ||
            (type == "directory");
        };

        # PIC side-module link flags (packr 0.8.x recipe). These MUST reach
        # the real cargo invocation. crane does NOT honor the repo
        # .cargo/config.toml (kept in-tree for devshell / plain-cargo builds),
        # so pass them via CARGO_ENCODED_RUSTFLAGS — highest cargo precedence,
        # cannot be shadowed by config. Flags are joined by 0x1f (ASCII unit
        # separator), cargo's encoded-rustflags delimiter.
        picSep = builtins.fromJSON "\"\\u001f\"";
        picRustflags = builtins.concatStringsSep picSep [
          "-C" "relocation-model=pic"
          "-C" "link-arg=--experimental-pic"
          "-C" "link-arg=-shared"
          "-C" "link-arg=--import-memory"
          "-C" "link-arg=--export=__wasm_call_ctors"
        ];

        commonArgs = {
          inherit src;
          pname = "frontdoor";
          version = "0.1.0";
          cargoExtraArgs = "--target wasm32-unknown-unknown";
          CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
          CARGO_ENCODED_RUSTFLAGS = picRustflags;
          doCheck = false;
        };

        # No buildDepsOnly: with the PIC link flags, crane's synthetic
        # deps-only dummy crate fails to link (-shared needs __heap_base/
        # __data_end, which only the real crates get from packr-guest's
        # `pic` feature). Build everything in one buildPackage pass instead.
        cargoArtifacts = null;

        theaterBin = theater.packages.${system}.default;

      in {
        # nix build — produces frontdoor.wasm in $out
        packages.default = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          installPhaseCommand = ''
            mkdir -p $out
            cp target/wasm32-unknown-unknown/release/frontdoor.wasm $out/
          '';
        });

        packages.theater = theaterBin;

        packages.clippy = craneLib.cargoClippy (commonArgs // {
          inherit cargoArtifacts;
          cargoClippyExtraArgs = "--target wasm32-unknown-unknown -- -D warnings";
        });

        packages.fmt = craneLib.cargoFmt {
          inherit src;
          pname = "frontdoor";
          version = "0.1.0";
        };

        devShells.default = craneLib.devShell {
          packages = [ rustToolchain theaterBin ];
          shellHook = ''
            echo "frontdoor dev environment"
            echo "  cargo build --release --target wasm32-unknown-unknown"
            echo "  theater start manifest.toml"
          '';
        };
      });
}
