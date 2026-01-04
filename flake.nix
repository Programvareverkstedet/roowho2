{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, rust-overlay}:
  let
    inherit (nixpkgs) lib;

    systems = [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
      "armv7l-linux"
    ];

    forAllSystems = f: nixpkgs.lib.genAttrs systems (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [
          (import rust-overlay)
        ];
      };

      rust-bin = rust-overlay.lib.mkRustBin { } pkgs.buildPackages;
      toolchain = rust-bin.stable.latest.default.override {
        extensions = [ "rust-src" ];
      };
    in f system pkgs toolchain);
  in {
    devShell = forAllSystems (system: pkgs: toolchain: pkgs.mkShell {
      nativeBuildInputs = with pkgs; [
        toolchain
        cargo-edit
      ];

      RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
    });

    overlays = {
      default = self.overlays.muscl;
      roowho2 = final: prev: {
        inherit (self.packages.${prev.stdenv.hostPlatform.system}) roowho2;
      };
    };

    nixosModules.default = ./nix/module.nix;

    packages = forAllSystems (system: pkgs: _:
      let
      cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
      cargoLock = ./Cargo.lock;
      src = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          ./src
          ./Cargo.toml
          ./Cargo.lock
        ];
      };
    in {
      default = self.packages.${system}.roowho2;

      roowho2 = pkgs.callPackage ./nix/default.nix { inherit cargoToml cargoLock src; };

      filteredSource = pkgs.runCommandLocal "filtered-source" { } ''
        ln -s ${src} $out
      '';
    });
  };
}
