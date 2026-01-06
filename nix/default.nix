{
  lib
, rustPlatform
, stdenv
, installShellFiles
, versionCheckHook

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

  meta = with lib; {
    license = licenses.mit;
    platforms = platforms.linux ++ platforms.darwin;
  };
}
