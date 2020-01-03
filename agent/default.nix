{ pkgs ? import ./nixpkgs.nix {} }:

with pkgs;

let
  inherit (rust.packages.nightly) rustPlatform;
in

{
  holo-router-agent = buildRustPackage rustPlatform {
    name = "holo-router-agent";
    src = gitignoreSource ./.;
    cargoDir = ".";

    nativeBuildInputs = [ pkgconfig ];
    buildInputs = [ openssl ];
  };
}
