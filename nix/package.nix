{
  lib
, rustPlatform
, stdenv
, buildPackages
, installShellFiles
, pkg-config
, versionCheckHook
, systemdLibs
, zstd
, libgit2

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

  buildInputs = [
    zstd
    libgit2
  ] ++ lib.optionals stdenv.hostPlatform.isLinux [
    systemdLibs
  ];

  nativeBuildInputs = [
    installShellFiles
    pkg-config
  ];
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
  in ''
    ${lib.concatStringsSep "\n" installShellCompletions}

    install -Dm444 assets/systemd/roowho2-audit.socket "$out/lib/systemd/system/roowho2-audit.socket"
    install -Dm444 assets/systemd/roowho2-client.socket "$out/lib/systemd/system/roowho2-client.socket"
    install -Dm444 assets/systemd/roowho2-rwhod.socket "$out/lib/systemd/system/roowho2-rwhod.socket"

    install -Dm444 assets/systemd/roowho2.service "$out/lib/systemd/system/roowho2.service"
    substituteInPlace "$out/lib/systemd/system/roowho2.service" \
      --replace "/usr/bin/roowhod" "${placeholder "out"}/bin/${mainProgram}"

    install -Dm444 assets/polkit/no.ntnu.pvv.roowho2.policy "$out/share/polkit-1/actions/no.ntnu.pvv.roowho2.policy"
    install -Dm444 assets/polkit/10-no.ntnu.pvv.roowho2.rules "$out/share/polkit-1/rules.d/10-no.ntnu.pvv.roowho2.rules"
  '';

  meta = with lib; {
    license = licenses.bsdOriginalUC;
    platforms = platforms.linux ++ platforms.darwin;
    inherit mainProgram;
  };
}
//
(if useCrane then craneArgs else rustPlatformArgs)
)
