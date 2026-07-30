{ config, pkgs, lib, utils, ... }:
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
              description = ''
                List of users/UIDs to ignore from the local machine both when
                broadcasting packets and when responding to local rwho/ruptime requests.

                If set to `null`, rwhod will not ignore any users, and will serve all users on the system.

                ::: {.note}
                This option is also available as `services.roowho2.settings.rwhod.ignoreUsers`,
                which is a more convenient way to specify the ignore list from within a NixOS module.
                :::
              '';
            };

            interfaces = lib.mkOption {
              type = with lib.types; nullOr (listOf str);
              default = null;
              example = [ "eth0" "wlan0" ];
              description = ''
                List of network interfaces to broadcast rwhod packets on.

                If set to `null`, rwhod will try to autodetect all reasonable interfaces
                to broadcast on, and use all of them.

                If set to an empty list, rwhod will not broadcast on any interfaces,
                and will only listen for incoming packets.
              '';
            };

            send_interval_seconds = lib.mkOption {
              type = lib.types.ints.positive;
              default = 60;
              description = ''
                Interval between rwhod status packet broadcasts.
              '';
            };

            max_status_entries = lib.mkOption {
              type = lib.types.ints.positive;
              default = 4096;
              description = ''
                Maximum number of distinct hosts to keep rwhod status records for
                at the same time. Once at capacity, the least recently updated
                record is evicted to make room for a newly-seen host.
              '';
            };

            realtime_updates = lib.mkOption {
              type = lib.types.bool;
              default = true;
              example = false;
              description = ''
                Whether to react to Linux audit log activity (e.g. logins/logouts)
                and push status updates immediately.
              '';
            };

            ignoreUsers = lib.mkOption {
              type = with lib.types; listOf (either str ints.unsigned);
              default = [ ];
              example = [ "user1" 1002 ];
              description = ''
                List of users/UIDs to ignore from the local machine both when
                broadcasting packets and when responding to local rwho/ruptime requests.

                If left empty, rwhod will not ignore any users, and will serve all users on the system.
              '';
            };

            socketConfig = lib.mkOption {
              type = utils.systemdUtils.unitOptions.unitOption;
              default = { };
              description = ''
                Config for the systemd socket's `[Socket]` section.

                See {manpage}`systemd.socket(5)` for details.
              '';
              example = {
                IPAddressDeny = "any";
                IPAddressAllow = [
                  "127.0.0.1"
                ];
              };
            };
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
              description = ''
                List of users/UIDs to ignore from the local machine when responding to
                local or remote finger requests.

                If set to `null`, fingerd will not ignore any users, and will serve all users on the system.

                ::: {.note}
                This option is also available as `services.roowho2.settings.fingerd.ignoreUsers`,
                which is a more convenient way to specify the ignore list from within a NixOS module.
                :::
              '';
            };

            ignoreUsers = lib.mkOption {
              type = with lib.types; listOf (either str ints.unsigned);
              default = [ ];
              example = [ "user1" 1002 ];
              description = ''
                List of users/UIDs to ignore from the local machine when responding to
                local or remote finger requests.

                If left empty, fingerd will not ignore any users, and will serve all users on the system.
              '';
            };

            # enable_remote_finger = lib.mkOption {
            #   type = lib.types.bool;
            #   default = false;
            #   example = true;
            #   description = ''
            #     Whether to allow remote finger requests.

            #     If set to false, only local finger requests will be served.
            #   '';
            # };

            # socketConfig = lib.mkOption {
            #   type = utils.systemdUtils.unitOptions.unitOption;
            #   default = { };
            #   description = ''
            #     Config for the systemd socket's `[Socket]` section.

            #     See {manpage}`systemd.socket(5)` for details.

            #     ::: {.note}
            #     This is only relevant if `enableRemoteFinger` is `true`.
            #     :::
            #   '';
            #   example = {
            #     IPAddressDeny = "any";
            #     IPAddressAllow = [
            #       "127.0.0.1"
            #     ];
            #   };
            # };
          };
        };
      };
      default = { };
      description = "Configuration settings for Roowho2.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.settings.rwhod.enable || cfg.settings.fingerd.enable;
        message = "At least one of `services.roowho2.settings.rwhod.enable` or `services.roowho2.settings.fingerd.enable` must be true.";
      }
      {
        assertion =
          cfg.settings.rwhod.ignoreUsers == [ ]
          || cfg.settings.rwhod.ignore_list_path == "/etc/roowho2/rwhod-ignore-list";
        message = "Cannot set both `services.roowho2.settings.rwhod.ignoreUsers` and `services.roowho2.settings.rwhod.ignore_list_path`.";
      }
      {
        assertion =
          cfg.settings.fingerd.ignoreUsers == [ ]
          || cfg.settings.fingerd.ignore_list_path == "/etc/roowho2/fingerd-ignore-list";
        message = "Cannot set both `services.roowho2.settings.fingerd.ignoreUsers` and `services.roowho2.settings.fingerd.ignore_list_path`.";
      }
    ];

    services.roowho2.settings = {
      rwhod.ignore_list_path =
        lib.mkIf
          (cfg.settings.rwhod.enable && cfg.settings.rwhod.ignoreUsers != [ ])
          "/etc/roowho2/rwhod-ignore-list";
      fingerd.ignore_list_path =
        lib.mkIf
          (cfg.settings.fingerd.enable && cfg.settings.fingerd.ignoreUsers != [ ])
          "/etc/roowho2/fingerd-ignore-list";
    };

    environment.etc = let
      generateIgnoreList = let
        nameToUidMapping = lib.pipe config.users.users [
          (lib.filterAttrs (_: user: user.uid != null))
          (lib.mapAttrsToList (name: user: { name = name; value = user.uid; }))
          lib.listToAttrs
        ];

        uidToNameMapping = lib.pipe config.users.users [
          (lib.filterAttrs (_: user: user.uid != null))
          (lib.mapAttrsToList (name: user: { name = toString user.uid; value = name; }))
          lib.listToAttrs
        ];
      in users: lib.pipe users [
        # Prefer UIDs for users we know the UID
        (map (user: if builtins.isString user
          then (nameToUidMapping.${user} or user)
          else user))

        # Then render back to strings
        (map (user:
           if builtins.isString user
             then "user:${user}"
             else "uid:${toString user} # ${uidToNameMapping.${toString user} or "unknown"}"))

        (lib.concatStringsSep "\n")
      ];
    in {
      "roowho2/rwhod-ignore-list" = lib.mkIf (cfg.settings.rwhod.enable && cfg.settings.rwhod.ignoreUsers != [ ]) {
        text = generateIgnoreList cfg.settings.rwhod.ignoreUsers;
      };

      "roowho2/fingerd-ignore-list" = lib.mkIf (cfg.settings.fingerd.enable && cfg.settings.fingerd.ignoreUsers != [ ]) {
        text = generateIgnoreList cfg.settings.fingerd.ignoreUsers;
      };
    };

    systemd.packages = [ cfg.package ];

    systemd.sockets.roowho2-client.wantedBy = lib.mkIf cfg.settings.rwhod.enable [ "sockets.target" ];
    systemd.sockets.roowho2-rwhod = lib.mkIf cfg.settings.rwhod.enable {
      wantedBy = [ "sockets.target" ];
      inherit (cfg.settings.rwhod) socketConfig;
    };
    systemd.sockets.roowho2-audit.wantedBy = lib.mkIf (cfg.settings.rwhod.enable && cfg.settings.rwhod.realtime_updates) [ "sockets.target" ];
    # systemd.sockets.roowho2-fingerd.wantedBy = lib.mkIf cfg.settings.fingerd.enable [ "sockets.target" ];

    systemd.services.roowho2 = {
      # Override the dbus system bus address to be where we bind-mounted it in the chroot.
      environment.DBUS_SYSTEM_BUS_ADDRESS = "unix:path=/run/dbus/system_bus_socket";

      serviceConfig = {
        ExecStart = let
          configFile = lib.pipe cfg.settings [
            (lib.filterAttrsRecursive (n: v: v != null))
            (settings: settings // {
              rwhod = lib.removeAttrs settings.rwhod [ "socketConfig" "ignoreUsers" ];
              fingerd = lib.removeAttrs settings.fingerd [ "socketConfig" "ignoreUsers" ];
            })
            (format.generate "roowho2-config.toml")
          ];
        in [
         ""
         "${lib.getExe' cfg.package "roowhod"} --config ${configFile}"
        ];

        RuntimeDirectory = "roowho2/root-mnt";
        RuntimeDirectoryMode = "0700";
        RootDirectory = "/run/roowho2/root-mnt";
        BindReadOnlyPaths = lib.filter (x: x != null) ([
          builtins.storeDir
          "/etc"

          # NOTE: need logind socket for utmp entries
          "/run/systemd"

          # NOTE: need dbus socket for polkit authorization
          "-/run/dbus/system_bus_socket"

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
      };
    };

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.settings.rwhod.enable [ 513 ];

    environment.systemPackages = [ cfg.package ];
  };
}
