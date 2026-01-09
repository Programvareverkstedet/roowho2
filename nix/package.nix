{
  lib
, rustPlatform
, stdenv
, buildPackages
, installShellFiles
, versionCheckHook
, systemdLibs

, cargoToml
, cargoLock
, src
}:
rustPlatform.buildRustPackage {
  pname = "roowho2";
  inherit (cargoToml.package) version;
  inherit src;

  cargoLock.lockFile = cargoLock;

  buildType = "releaselto";

  RUSTFLAGS = "-Zhigher-ranked-assumptions";

  buildFeatures = lib.optionals stdenv.hostPlatform.isLinux [
    "systemd"
  ];

  buildInputs = lib.optionals stdenv.hostPlatform.isLinux [
    systemdLibs
  ];

  nativeBuildInputs = [ installShellFiles ];
  postInstall = let
    emulator = stdenv.hostPlatform.emulator buildPackages;
    installShellCompletions = lib.mapCartesianProduct ({ shell, command }: ''
      (
        export PATH="$out/bin:$PATH"
        "${emulator}" "${command}" --completions=${shell} > "$TMP/${command}.${shell}"
      )
      installShellCompletion "--${shell}" --cmd "${command}" "$TMP/${command}.${shell}"
    '') {
      shell = [ "bash" "zsh" "fish" ];
      command = [ "rwho" "ruptime" ];
    };
  in lib.concatStringsSep "\n" installShellCompletions;

  meta = with lib; {
    license = licenses.mit;
    platforms = platforms.linux ++ platforms.darwin;
  };
}
