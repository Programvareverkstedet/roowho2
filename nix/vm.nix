{ self, nixpkgs, ... }:
nixpkgs.lib.nixosSystem {
  system = "x86_64-linux";
  pkgs = import nixpkgs {
    system = "x86_64-linux";
    overlays = [
      self.overlays.roowho2
    ];
  };
  modules = [
    "${nixpkgs}/nixos/modules/virtualisation/qemu-vm.nix"
    "${nixpkgs}/nixos/tests/common/user-account.nix"

    self.nixosModules.default

    ({ config, pkgs, ... }: {
      system.stateVersion = config.system.nixos.release;
      virtualisation.graphics = false;

      users.users.alice.extraGroups = [ "wheel" ];

      services.getty.autologinUser = "alice";

      users.motd = ''
        =================================
        Welcome to the roowho2 vm!

        Try running any of:
            rwho

        Password for alice is 'foobar'

        To exit, press Ctrl+A, then X
        =================================
      '';

      services.roowho2 = {
        enable = true;
      };

      programs.vim = {
        enable = true;
        defaultEditor = true;
      };

      environment.systemPackages = with pkgs; [ jq roowho2 ];
    })
  ];
}
