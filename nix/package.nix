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

, useCrane ? false
, craneLib ? null
}:
let
  mainProgram = "roowhod";
  buildFunction = if useCrane then craneLib.buildPackage else rustPlatform.buildRustPackage;

  pnameCraneSuffix = lib.optionalString useCrane "-crane";
  pname = "${cargoToml.package.name}${pnameCraneSuffix}";

  rustPlatformArgs = {
    buildType = "releaselto";
    buildFeatures = lib.optionals stdenv.hostPlatform.isLinux [
      "systemd"
    ];
    cargoLock.lockFile = cargoLock;

    doCheck = true;
    useNextest = true;
    nativeCheckInputs = [
      versionCheckHook
    ];
    cargoCheckFeatures = lib.optionals stdenv.hostPlatform.isLinux [
      "systemd"
    ];
  };

  craneArgs = {
    cargoLock = cargoLock;
    cargoExtraArgs = lib.escapeShellArgs [ "--features" (lib.concatStringsSep "," (
      lib.optionals stdenv.hostPlatform.isLinux [
        "systemd"
      ]
    )) ];
    cargoArtifacts = craneLib.buildDepsOnly {
      inherit pname;
      inherit (cargoToml.package) version;
      src = lib.fileset.toSource {
        root = ../.;
        fileset = lib.fileset.unions [
          (craneLib.fileset.cargoTomlAndLock ../.)
        ];
      };

      cargoLock = cargoLock;
    };
  };
in
buildFunction ({
  inherit pname;
  inherit (cargoToml.package) version;
  inherit src;

  RUSTFLAGS = "-Zhigher-ranked-assumptions";

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
      command = [ "rwho" "ruptime" "finger" "wall" "write" ];
    };
  in lib.concatStringsSep "\n" installShellCompletions;

  meta = with lib; {
    license = licenses.bsdOriginalUC;
    platforms = platforms.linux ++ platforms.darwin;
    inherit mainProgram;
  };
}
//
(if useCrane then craneArgs else rustPlatformArgs)
)
