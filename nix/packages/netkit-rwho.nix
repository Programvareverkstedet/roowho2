{
  lib,
  stdenv,
  fetchurl,
  fetchpatch,

  cmake,
}:
stdenv.mkDerivation (finalAttrs: {
  pname = "netkit-rwho";
  version = "0.17-14";

  src = fetchurl {
    url = "https://deb.debian.org/debian/pool/main/n/netkit-rwho/netkit-rwho_0.17.orig.tar.gz";
    hash = "sha256-BAnizkv9strLLBk9D+38SbuXXLBXxcaw/8ymA6EYjac=";
  };

  patches = let
    url = name: "https://sources.debian.org/data/main/n/netkit-rwho/${finalAttrs.version}/debian/patches/${name}.patch";
  in [
    (fetchpatch {
      url = url "pre-0.17-13-changes";
      hash = "sha256-t5WdtDgY1lX0vUE3JOB0eSZ75UsTppacNxSCeVYbzGg=";
    })
    (fetchpatch {
      url = url "show_in_all_ifaces";
      hash = "sha256-S9idU0A64SnQQ/QCtrLJ4qFxRGeKvAL/9hisbTGWi6M=";
    })
    (fetchpatch {
      url = url "use-cmake-as-buildsystem";
      hash = "sha256-pyDa9aObnwJ4qjDUskybYGhcJG3pZ6HHbJguerm2UpM=";
    })
  ];

  # FIXME: this is not working as intended,
  #        `strings $out/bin/* still shows a bunch of /var/spool/who dirs
  postPatch = ''
    for f in $(find . -type f); do
        if grep -q "/var/spool/rwho" "$f"; then
          substituteInPlace "$f" --replace "/var/spool/rwho" "/var/lib/rwho"
        fi
    done
  '';

  nativeBuildInputs = [ cmake ];

  meta = {
    license = lib.licenses.bsdOriginal;
    mainProgram = "rwho";
    maintainers = [ lib.maintainers.h7x4 ];
    platforms = lib.platforms.linux;
  };
})
