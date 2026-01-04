{ config, pkgs, lib, ... }:
let
  cfg = config.services.roowho2;
  format = pkgs.formats.toml { };
in {
  options.services.roowho2 = {
    enable = lib.mkEnableOption "the roowho2 daemon, replacement for multiple linux netkit services";
    package = lib.mkPackageOption pkgs "roowho2" { };

    settings = lib.mkOption {
      type = lib.types.submodule {
        freeformType = format.type;
        options = {
          rwhod = {
            enable = lib.mkEnableOption "the rwhod service";

            # TODO: allow configuring socket config
          };
        };
      };
      default = { };
      description = "Configuration settings for Roowho2.";
    };
  };

  config = lib.mkIf cfg.enable {

    systemd.sockets.roowhoo2-rwhod = lib.mkIf cfg.settings.rwhod.enable {
      description = "Roowho2 Rwhod Socket";
      listenDatagrams = [ 513 ];
      socketConfig = {
        Service = "roowho2.service";
        FileDescriptorName = "rwhod_socket";
        Broadcast = true;
      };
    };

    systemd.services.roowho2 = {
      serviceConfig = {
        ExecStart = "${lib.getExe' cfg.package "roowho2d"} --config ${format.toFile cfg.settings}";
        Restart = "on-failure";
        DynamicUser = true;

        # TODO: hardening
      };
    };
  };
}
