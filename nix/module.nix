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
          log_level = lib.mkOption {
            type = lib.types.enum [ "info" "debug" "trace" ];
            default = "info";
            description = "Log level for the roowho2 daemon.";
          };

          rwhod = {
            enable = lib.mkEnableOption "the rwhod service" // {
              default = true;
            };

            ignore_list_path = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              example = lib.literalExpression ''
                pkgs.writeText "rwhod-ignore-list" '''
                  # Ignore the following users from rwhod
                  user:user1
                  user:user2
                  uid:1001
                '''
              '';
              description = "Path to the ignore list for users that should be hidden from rwhod.";
            };

            # TODO: allow configuring socket config
          };
          fingerd = {
            enable = lib.mkEnableOption "the fingerd service" // {
              default = true;
            };

            ignore_list_path = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              example = lib.literalExpression ''
                pkgs.writeText "fingerd-ignore-list" '''
                  # Ignore the following users from rwhod
                  user:user1
                  user:user2
                  uid:1001
                '''
              '';
              description = "Path to the ignore list for users that should be hidden from fingerd.";
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
      listenDatagrams = [ "0.0.0.0:513" ];
      socketConfig = {
        Service = "roowho2.service";
        FileDescriptorName = "rwhod_socket";
        Broadcast = true;
      };
    };

    systemd.services.roowho2 = {
      serviceConfig = {
        Type = "notify";
        ExecStart = "${lib.getExe' cfg.package "roowhod"} --config ${format.generate "roowho2-config.toml" cfg.settings}";
        Restart = "on-failure";
        DynamicUser = true;

        # NOTE: roowho2 might at some point need to read from home directories
        #       to get user settings, so let's keep these disabled for now.
        # PrivateUsers = true;
        # ProtectHome = true;

        # NOTE: We need this capability to be able to read inside the home directories of users without
        #       them needing to open their homedirs to the rest of the system.
        AmbientCapabilities = [ "CAP_DAC_READ_SEARCH" ];
        CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH" ];
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
        BindReadOnlyPaths = lib.filter (x: x != null) ([
          builtins.storeDir
          "/etc"

          # NOTE: need logind socket for utmp entries
          "/run/systemd"

          "/home"

          # NOTE: finger might need access to mail directories
          "-/var/spool"
          "-/var/mail"

          # NOTE: finger needs access to stat tty devices
          "/dev"

        ] ++ lib.optionals cfg.settings.rwhod.enable [
          cfg.settings.rwhod.ignore_list_path
        ] ++ lib.optionals cfg.settings.fingerd.enable [
          cfg.settings.fingerd.ignore_list_path
        ]);

        UMask = "0077";
      };
    };

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.settings.rwhod.enable [ 513 ];

    environment.systemPackages = [ cfg.package ];
  };
}
