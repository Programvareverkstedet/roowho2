{ ... }:
{
  name = "rwhod";

  nodes = {
    host1 = { pkgs, ... }: {
      imports = [ ../module.nix ];

      boot.kernelParams = [ "audit=1" ];

      environment.systemPackages = [ pkgs.screen ];

      services.roowho2 = {
        enable = true;
        settings = {
          log_level = "debug";
          rwhod = {
            enable = true;
            # Effectively infinite interval means host1 will never announce itself
            # to the network in a periodic broadcast. We will force it to do so
            # via the realtime push mechanism when a user logs in or out.
            send_interval_seconds = 99999999;
          };
          fingerd.enable = false;
        };
      };

      users.users.alice.isNormalUser = true;
    };

    host2 = { pkgs, ... }: {
      imports = [ ../module.nix ];

      environment.systemPackages = [ pkgs.screen ];

      services.roowho2 = {
        enable = true;
        settings = {
          log_level = "debug";
          rwhod = {
            enable = true;
            send_interval_seconds = 5;
          };
          fingerd.enable = false;
        };
      };

      users.users.bob.isNormalUser = true;

      specialisation.ignore-bob.configuration = {
        services.roowho2.settings.rwhod.ignoreUsers = [ "bob" ];
      };
    };

    host3 = { ... }: {
      imports = [ ../module.nix ];

      services.roowho2 = {
        enable = true;
        settings = {
          log_level = "debug";
          rwhod = {
            enable = true;
            send_interval_seconds = 5;
            # Without any interfaces to broadcast on,
            # this host will never announce itself to the network.
            interfaces = [ ];
          };
          fingerd.enable = false;
        };
      };
    };
  };

  testScript = ''
    import json

    def rwho_entries(machine):
        return json.loads(machine.succeed("rwho --all --json"))

    def ruptime_entries(machine):
        return json.loads(machine.succeed("ruptime --all --json"))

    def find_ruptime_entry(entries, hostname):
        return next((e for e in entries if e["hostname"] == hostname), None)

    def find_rwho_user(entries, hostname, username):
        return next(
            (user for user in entries.get(hostname, []) if user["user_id"] == username),
            None,
        )

    def wait_for_host_in_ruptime(machine, hostname, present=True, timeout=300):
        def check(_last_try):
            found = find_ruptime_entry(ruptime_entries(machine), hostname) is not None
            return found == present
        retry(check, timeout_seconds=timeout)

    def wait_for_user_in_rwho(machine, hostname, username, present=True, timeout=300):
        def check(_last_try):
            found = find_rwho_user(rwho_entries(machine), hostname, username) is not None
            return found == present
        retry(check, timeout_seconds=timeout)

    def start_session(machine, username, session_name):
        machine.succeed(f"screen -dmS {session_name} login -f {username}")

    def stop_session(machine, session_name):
        machine.succeed(f"screen -S {session_name} -X quit")

    start_all()
    for machine in [host1, host2, host3]:
        machine.wait_for_unit("roowho2-rwhod.socket")
        machine.wait_for_unit("roowho2-client.socket")
        machine.wait_for_unit("multi-user.target")
        machine.succeed("ruptime --all --json")

    with subtest("host2 broadcasts its status periodically"):
        host2.wait_for_console_text(r"Sending rwhod packet to interface")
        wait_for_host_in_ruptime(host1, "host2", timeout=20)
        wait_for_host_in_ruptime(host3, "host2", timeout=20)

    with subtest("Check host2 ruptime fields"):
        entry = find_ruptime_entry(ruptime_entries(host1), "host2")
        assert entry is not None, "Expected host2 to be present in host1's ruptime"
        assert entry["users"] == [], f"Expected no users logged in yet, got: {entry!r}"

    with subtest("Starting a session on host1 triggers a realtime status push"):
        start_session(host1, "alice", "alice-session")
        wait_for_user_in_rwho(host2, "host1", "alice")
        wait_for_user_in_rwho(host3, "host1", "alice")

    with subtest("Stopping a session on host1 triggers a realtime status push"):
        stop_session(host1, "alice-session")
        wait_for_user_in_rwho(host2, "host1", "alice", present=False)
        wait_for_user_in_rwho(host3, "host1", "alice", present=False)

    with subtest("Starting a session on host2 eventually becomes visible"):
        start_session(host2, "bob", "bob-session")
        wait_for_user_in_rwho(host1, "host2", "bob")
        wait_for_user_in_rwho(host3, "host2", "bob")

    with subtest("Switching host2 to ignore bob removes them from the next broadcast"):
        host2.succeed(
            "/run/current-system/specialisation/ignore-bob/bin/switch-to-configuration test"
        )
        host2.wait_for_unit("roowho2-client.socket")
        host2.succeed("who | grep bob") # Ensure bob is still logged in
        wait_for_user_in_rwho(host1, "host2", "bob", present=False)
        wait_for_user_in_rwho(host3, "host2", "bob", present=False)

    with subtest("host3's interfaces allowlist keeps it from ever broadcasting"):
        assert find_ruptime_entry(ruptime_entries(host1), "host3") is None, (
            "host1 should not have learned about host3"
        )
        assert find_ruptime_entry(ruptime_entries(host2), "host3") is None, (
            "host2 should not have learned about host3"
        )
        wait_for_host_in_ruptime(host3, "host1")
        wait_for_host_in_ruptime(host3, "host2")
  '';
}
