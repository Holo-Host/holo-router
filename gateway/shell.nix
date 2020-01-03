{ pkgs ? import ./nixpkgs.nix {} }:

with pkgs;

mkShell {
  inputsFrom = with import ../. { inherit pkgs; }; [
    holo-router-gateway
  ];
}
