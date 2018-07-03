use std::process::Command;

fn main() {
    // Generate contracts.
    let status = Command::new("truffle")
        .arg("compile")
        .status()
        .expect("truffle failed to build");
    assert!(status.success());

    println!(
        "cargo:rerun-if-changed={}",
        "contracts/ContractRegistry.sol"
    );
    println!("cargo:rerun-if-changed={}", "contracts/EntityRegistry.sol");
    println!("cargo:rerun-if-changed={}", "contracts/MockEpoch.sol");
    println!("cargo:rerun-if-changed={}", "contracts/OasisEpoch.sol");
    println!("cargo:rerun-if-changed={}", "contracts/RandomBeacon.sol");
    println!("cargo:rerun-if-changed={}", "contracts/Stake.sol");
}
