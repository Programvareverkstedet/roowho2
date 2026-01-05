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
            enable = lib.mkEnableOption "the rwhod service" // {
              default = true;
            };

            # TODO: allow configuring socket config
          };
        };
      };
      default = { };
      description = "Configuration settings for Roowho2.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.sockets.roowho2-client = {
      wantedBy = [ "sockets.target" ];
      description = "Roowho2 Client Communication Socket";
      listenStreams = [ "/run/roowho2/roowho2.varlink" ];
      socketConfig = {
        Service = "roowho2.service";
        FileDescriptorName = "client_socket";
      };
    };

    systemd.sockets.roowho2-rwhod = lib.mkIf cfg.settings.rwhod.enable {
      wantedBy = [ "sockets.target" ];
      description = "Roowho2 Rwhod Socket";
      listenDatagrams = [ (toString 513) ];
      socketConfig = {
        Service = "roowho2.service";
        FileDescriptorName = "rwhod_socket";
        Broadcast = true;
      };
    };

    systemd.services.roowho2 = {
      serviceConfig = {
        ExecStart = "${lib.getExe' cfg.package "roowhod"} --config ${format.generate "roowho2-config.toml" cfg.settings}";
        Restart = "on-failure";
        DynamicUser = true;

        # TODO: hardening
      };
    };
  };
}
