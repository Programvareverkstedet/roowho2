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
          fingerd = {
            enable = lib.mkEnableOption "the fingerd service" // {
              default = true;
            };

            # TODO: allow configuring socket config
          };
        };
      };
      default = { };
      description = "Configuration settings for Roowho2.";
    };

    logLevel = lib.mkOption {
      type = lib.types.enum [ "quiet" "info" "debug" "trace" ];
      default = "info";
      description = "Log level for the roowho2 daemon.";
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
      listenDatagrams = [ "0.0.0.0:513" ];
      socketConfig = {
        Service = "roowho2.service";
        FileDescriptorName = "rwhod_socket";
        Broadcast = true;
      };
    };

    systemd.services.roowho2 = {
      environment.RUST_LOG = cfg.logLevel;
      serviceConfig = {
        Type = "notify";
        ExecStart = "${lib.getExe' cfg.package "roowhod"} --config ${format.generate "roowho2-config.toml" cfg.settings}";
        Restart = "on-failure";
        DynamicUser = true;

        # NOTE: roowho2 might at some point need to read from home directories
        #       to get user settings, so let's keep these disabled for now.
        # PrivateUsers = true;
        # ProtectHome = true;

        AmbientCapabilities = "";
        CapabilityBoundingSet = "";
        DeviceAllow = "";
        DevicePolicy = "closed";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        # NOTE: all ipc traffic is served through the socket activation fds or provided by systemd
        PrivateIPC = true;
        PrivateMounts = true;
        PrivateTmp = true;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = "strict";
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        RemoveIPC = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
          "AF_NETLINK"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SocketBindDeny = "any";
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
          "~@resources"
        ];

        RuntimeDirectory = "roowho2/root-mnt";
        RuntimeDirectoryMode = "0700";
        RootDirectory = "/run/roowho2/root-mnt";
        BindReadOnlyPaths = [
          builtins.storeDir
          "/etc"

          # NOTE: need logind socket for utmp entries
          "/run/systemd"

          "/home"

          # NOTE: finger might need access to mail directories
          "-/var/spool"
          "-/var/mail"
        ];

        UMask = "0077";
      };
    };

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.settings.rwhod.enable [ 513 ];

    environment.systemPackages = [ cfg.package ];
  };
}
