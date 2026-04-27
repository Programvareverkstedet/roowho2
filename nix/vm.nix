{ self, nixpkgs, ... }:
let
  system = "x86_64-linux";
  pkgs = import nixpkgs {
    inherit system;
    overlays = [
      self.overlays.roowho2-crane
    ];
  };
in
nixpkgs.lib.nixosSystem {
  inherit system pkgs;
  modules = [
    "${nixpkgs}/nixos/modules/virtualisation/qemu-vm.nix"
    "${nixpkgs}/nixos/tests/common/user-account.nix"

    self.nixosModules.default

    ({ config, lib, ... }: {
      system.stateVersion = config.system.nixos.release;
      virtualisation.graphics = false;

      virtualisation.memorySize = 256;
      virtualisation.vlans = [ 1 ];

      users.users.alice.extraGroups = [ "wheel" ];

      services.getty.autologinUser = "alice";

      users.motd = ''
        =================================
        Welcome to the roowho2 vm!

        Try running any of:
            rwho
            ruptime
            finger "alice"

        To log into other containers, use:
            machinectl shell c1
            machinectl shell c2

        Password for alice is 'foobar'

        To exit, press Ctrl+A, then X
        =================================
      '';

      services.roowho2 = {
        enable = true;
        logLevel = "debug";
      };

      programs.vim = {
        enable = true;
        defaultEditor = true;
      };

      security.polkit.enable = true;

      networking = {
        useNetworkd = true;
        macvlans.mv-eth0-host = {
          interface = "eth0";
          mode = "bridge";
        };
      };

      systemd.network.enable = true;
      systemd.network.networks."mv-eth0-host" = {
        matchConfig.Name = "mv-eth0-host";
        gateway = [
          "10.0.0.255"
        ];
        DHCP = "no";
        address =  [
          "10.0.0.128/24"
        ];
      };

      containers = let
        commonContainerConfig = n: {
          autoStart = true;
          macvlans = [ "eth0" ];
          config = {
            imports = [
              "${nixpkgs}/nixos/tests/common/user-account.nix"
              self.nixosModules.default
            ];
            system.stateVersion = config.system.nixos.release;
            nixpkgs.pkgs = pkgs;

            networking = {
              hostName = "c${toString n}";
              useDHCP = false;
              useNetworkd = true;
              useHostResolvConf = false;
            };

            systemd.network.enable = true;
            systemd.network.networks."mv-eth0" = {
              matchConfig.Name = "mv-eth0";
              gateway = [ "10.0.0.255" ];
              address = [ "10.0.0.${toString n}/24" ];
              dhcpV4Config.ClientIdentifier = "mac";
            };

            users.users.alice.extraGroups = [ "wheel" ];

            users.motd = ''
              =================================
              Welcome to the roowho2 c${toString n} container!

              Try running any of:
                  rwho
                  ruptime

              Password for alice is 'foobar'
              =================================
            '';

            services.roowho2 = {
              enable = true;
            };

            programs.vim = {
              enable = true;
              defaultEditor = true;
            };
          };
        };
      in {
        c1 = commonContainerConfig 1;
        c2 = commonContainerConfig 2;
      };
    })
  ];
}
