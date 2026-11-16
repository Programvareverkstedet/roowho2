{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";

    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, rust-overlay, crane }:
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
      toolchain = rust-bin.nightly.latest.minimal.override {
        extensions = [ "rust-src" "clippy" "rustfmt" ];
      };
    in f system pkgs toolchain);
  in {
    apps = let
      mkApp = program: description: {
        type = "app";
        program = toString program;
        meta = {
          inherit description;
        };
      };
      mkVm = name: mkApp "${self.nixosConfigurations.${name}.config.system.build.vm}/bin/run-nixos-vm";
    in forAllSystems (system: pkgs: _: {
      vm = mkVm "vm" "Start a NixOS VM with roowho2 installed";
    });

    nixosConfigurations = {
      vm = import ./nix/vm.nix { inherit self nixpkgs; };
    };

    devShell = forAllSystems (system: pkgs: toolchain: pkgs.mkShell {
      nativeBuildInputs = with pkgs; [
        toolchain
        cargo-edit
        cargo-deb
      ] ++ (lib.optionals stdenv.buildPlatform.isLinux [
        systemdLibs
      ]);

      env = {
        RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
        RUSTFLAGS = "-Zhigher-ranked-assumptions";
        CARGO_CFG_FEATURE = lib.concatStringsSep "," (lib.optionals pkgs.stdenv.buildPlatform.isLinux [
          "systemd"
        ]);
      };
    });

    overlays = {
      default = self.overlays.roowho2;
      roowho2 = final: prev: {
        inherit (self.packages.${prev.stdenv.hostPlatform.system}) roowho2;
      };
      roowho2-crane = final: prev: {
        roowho2 = self.packages.${prev.stdenv.hostPlatform.system}.roowho2-crane;
      };
    };

    nixosModules.default = ./nix/module.nix;

    packages = forAllSystems (system: pkgs: _:
      let
      cargoToml = fromTOML (builtins.readFile ./Cargo.toml);
      cargoLock = ./Cargo.lock;
      craneLib = (crane.mkLib pkgs).overrideToolchain(p: p.rust-bin.nightly.latest.minimal);

      src = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          (craneLib.fileset.commonCargoSources ./.)
          ./assets/systemd
          ./assets/polkit
        ];
      };

      rustPlatform = pkgs.makeRustPlatform {
        rustc = pkgs.rust-bin.nightly.latest.minimal;
        cargo = pkgs.rust-bin.nightly.latest.minimal;
      };
    in {
      default = self.packages.${system}.roowho2-crane;

      roowho2 = pkgs.callPackage ./nix/package.nix {
        inherit cargoToml cargoLock src rustPlatform;
      };

      roowho2-crane = pkgs.callPackage ./nix/package.nix {
        useCrane = true;
        inherit cargoToml cargoLock src craneLib;
      };

      filteredSource = pkgs.runCommandLocal "filtered-source" { } ''
        ln -s ${src} $out
      '';

      netkit-rwho = pkgs.callPackage ./nix/packages/netkit-rwho.nix { };
    });

    checks = forAllSystems (system: pkgs: _: {
      # NOTE: the non-crane build runs tests during checkPhase
      inherit (self.packages.${system}) roowho2;
    });

    tests = forAllSystems (system: pkgs: _: let
      pkgs' = pkgs.extend self.overlays.default;
    in
       import ./nix/tests { pkgs = pkgs'; }
    );
  };
}
