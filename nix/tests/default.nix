{ pkgs, ... }:
{
  # Backwards compatibility tests
  # bsd-fingerd = pkgs.testers.runNixOSTest ./bsd-fingerd.nix;
  # netkit-rwho = pkgs.testers.runNixOSTest ./netkit-rwho.nix;

  # roowho2 integration tests
  rwhod = pkgs.testers.runNixOSTest ./rwhod.nix;
  # fingerd = pkgs.testers.runNixOSTest ./fingerd.nix;
}
