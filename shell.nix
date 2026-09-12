{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = with pkgs; [
    nmap
    wireshark
    tcpdump
    python3
    esptool
    ghidra
  ];
  shellHook = ''
    echo "roku-bulb-local lab shell: nmap, tshark, tcpdump, esptool ready"
  '';
}
