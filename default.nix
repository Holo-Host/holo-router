{ pkgs ? import ./nixpkgs.nix {} }:

with pkgs;

let
  inherit (rust.packages.stable) rustPlatform;
in

{
  holo-router-agent = buildRustPackage rustPlatform {
    name = "holo-router-agent";
    src = gitignoreSource ./.;
    cargoDir = "./agent";

    nativeBuildInputs = [ pkgconfig ];
    buildInputs = [ openssl ];

    meta.platforms = lib.platforms.linux;
  };

  holo-router-gateway = buildRustPackage rustPlatform {
    name = "holo-router-gateway";
    src = gitignoreSource ./.;
    cargoDir = "./gateway";

    meta.platforms = lib.platforms.linux;
  };
}
