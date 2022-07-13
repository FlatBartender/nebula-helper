use clap::{Parser, Subcommand, Args};
use serde::{Serialize, Deserialize};
use std::{net::Ipv4Addr, process::Command, collections::HashSet, io::{Read, Write}, fs::{remove_file, File}};
use anyhow::{ensure, Result, anyhow};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct NebulaHelperOptions {
    #[clap(subcommand)]
    command: NebulaHelperCommand,
    #[clap(short, long)]
    network: String,
}

#[derive(Subcommand, Debug)]
enum NebulaHelperCommand {
    AddHost(Host),
    RemoveHost { name: String },
    ShowHost { name: String, #[clap(short, long)] yaml: bool },
    CreateNetwork(Network),
}

#[derive(Args, Debug, Serialize, Deserialize)]
struct Network {
    #[clap(short, long)]
    address: Ipv4Addr,

    #[clap(skip)]
    hosts: Vec<Host>,
    #[clap(skip)]
    certificate: String,
    #[clap(skip)]
    key: String,
}

impl Network {
    fn load_from_file<D: std::fmt::Display>(name: D) -> Result<Network> {
        let network_path = format!("{}.yaml", name);
        let network_file = std::fs::File::open(&network_path)?;
        Ok(serde_yaml::from_reader(network_file)?)
    }

    fn save_to_file<D: std::fmt::Display>(&self, name: D) -> Result<()> {
        let network_path = format!("{}.yaml", name);
        let network_file = std::fs::File::create(&network_path)?;
        serde_yaml::to_writer(network_file, self)?;
        Ok(())
    }

    fn next_ip(&self) -> Option<(Ipv4Addr, u32)> {
        let base = u32::from(self.address);
        let range = base.trailing_zeros();

        let used_addresses: HashSet<_> = self.hosts.iter()
            .map(|host| host.ip.unwrap())
            .collect();

        let next_address = (base..=base + (1 << range))
            .filter(|addr| (addr & 255) != 0 && (addr & 255) != 255)
            .map(|addr| Ipv4Addr::from(addr))
            .filter(|addr| !used_addresses.contains(addr))
            .next()?;

        Some((next_address, range))
    }

    fn check_ip(&self, addr: Ipv4Addr) -> Option<(Ipv4Addr, u32)> {
        let base = u32::from(self.address);
        let range = base.trailing_zeros();
        let addr_int = u32::from(addr);

        if !(base..=base + (1 << range)).contains(&addr_int) {
            return None;
        }

        let last_byte = addr_int & 255;
        if last_byte == 255 || last_byte == 0 {
            return None;
        }

        let used_addresses: HashSet<_> = self.hosts.iter()
            .map(|host| host.ip.unwrap())
            .collect();

        if used_addresses.contains(&addr) {
            return None;
        }

        Some((addr, range))
    }

    fn check_subnet(&self) -> bool {
        if !self.address.is_private() {
            println!("Address isn't private");
            return false;
        }

        let addr = u32::from(self.address);
        let upper = addr + (1 << addr.trailing_zeros());
        if !Ipv4Addr::from(upper).is_private() {
            println!("Uppper: {}", upper);
            return false;
        }

        true
    }
}

#[derive(Args, Debug, Serialize, Deserialize)]
struct Host {
    #[clap(short, long)]
    name: String,
    #[clap(short, long)]
    groups: Vec<String>,
    #[clap(long)]
    roaming: bool,
    #[clap(short, long)]
    ip: Option<Ipv4Addr>,
    #[clap(short = 'l', long)]
    is_lighthouse: bool,
    #[clap(short = 'r', long)]
    is_relay: bool,
    #[clap(short, long, default_value = "")]
    external_ip: String,

    #[serde(skip)]
    #[clap(short, long, default_value = "")]
    public_key_file: String,

    #[clap(skip)]
    certificate: String,
    #[clap(skip)]
    private_key: String,
}

fn main() -> Result<()> {
    let options = NebulaHelperOptions::parse();
    match options {
        NebulaHelperOptions { network: network_name, command: NebulaHelperCommand::AddHost(host) } => add_host(network_name, host),
        NebulaHelperOptions { network: network_name, command: NebulaHelperCommand::RemoveHost { name } } => remove_host(network_name, name),
        NebulaHelperOptions { network: network_name, command: NebulaHelperCommand::ShowHost { name, yaml } } => show_host(network_name, name, yaml),
        NebulaHelperOptions { network: network_name, command: NebulaHelperCommand::CreateNetwork(network) } => create_network(network_name, network),
    }
}

fn add_host(network_name: String, mut host: Host) -> Result<()> {
    let mut network = Network::load_from_file(&network_name)?;

    if host.external_ip.is_empty() && host.is_lighthouse {
        return Err(anyhow!("Lighthouses must have an external IP"));
    }

    let (address, range) = match host.ip {
        None => network.next_ip().ok_or(anyhow!("network IP range full")),
        Some(ip) => network.check_ip(ip).ok_or(anyhow!("{} is invalid for network IP range", ip)),
    }?;

    host.ip = Some(address);

    let mut command = Command::new("nebula-cert");
    let ip = format!("{}/{}", address, range);
    command.args(["sign", "-name", &host.name, "-ip", &ip, "-out-crt", "client.crt"]);

    if !host.groups.is_empty() {
        command.args(["-groups", &host.groups.join(",")]);
    }

    if !host.public_key_file.is_empty() {
        command.args(["-in-pub", &host.public_key_file]);
    } else {
        command.args(["-out-key", "client.key"]);
    }

    let mut ca_key_file = tempfile::NamedTempFile::new()?;
    ca_key_file.write_all(network.key.as_bytes())?;
    command.arg("-ca-key")
        .arg(ca_key_file.path());
    let mut ca_crt_file = tempfile::NamedTempFile::new()?;
    ca_crt_file.write_all(network.certificate.as_bytes())?;
    command.arg("-ca-crt")
        .arg(ca_crt_file.path());

    let status = command.status()?;

    if !status.success() {
        return Err(anyhow!("nebula-cert did not execute successfully"));
    }

    let mut crt = String::with_capacity(512);
    std::fs::File::open("client.crt")?.read_to_string(&mut crt)?;
    std::fs::remove_file("client.crt")?;
    host.certificate = crt;

    if host.public_key_file.is_empty() {
        let mut key = String::with_capacity(512);
        std::fs::File::open("client.key")?.read_to_string(&mut key)?;
        std::fs::remove_file("client.key")?;
        host.private_key = key;
    }

    network.hosts.push(host);

    network.save_to_file(&network_name)?;

    Ok(())
}

fn remove_host(network_name: String, name: String) -> Result<()> {
    let mut network = Network::load_from_file(&network_name)?;

    let new_hosts: Vec<_> = network.hosts.into_iter()
        .filter(|host| host.name != name)
        .collect();

    network.hosts = new_hosts;

    network.save_to_file(&network_name)?;

    Ok(())
}

fn show_host(network_name: String, name: String, yaml: bool) -> Result<()> {
    let network = Network::load_from_file(&network_name)?;

    let host = if let Some(host) = network.hosts.iter().find(|host| host.name == name) {
        host
    } else {
        return Err(anyhow!("Client configuration not found"));
    };

    match yaml {
        false => host_infos_no_yaml(&network_name, &network, host)?,
        true => host_infos_yaml(&name, &network, host)?,
    }

    Ok(())
}

fn host_infos_no_yaml<D: std::fmt::Display>(network_name: D, network: &Network, host: &Host) -> Result<()> {
    use qrcode::{QrCode, render::unicode};

    println!("Network: {}", network_name);
    println!("Host: {}", host.name);
    println!("");

    let host_certificate = QrCode::new(&host.certificate)?;
    let ca_certificate = QrCode::new(&network.certificate)?;

    println!("Host certificate:");
    println!("{}", host_certificate.render::<unicode::Dense1x2>().build());

    println!("CA certificate:");
    println!("{}", ca_certificate.render::<unicode::Dense1x2>().build());

    println!("Static hosts (internal | external):");
    for static_host in network.hosts.iter().filter(|host| !host.external_ip.is_empty()) {
        print!("    {} | {}", static_host.ip.clone().unwrap(), static_host.external_ip);
        if static_host.is_lighthouse && !host.is_lighthouse {
            print!(" (lighthouse)");
        }
        println!("");
    }

    Ok(())
}

const CLIENT_CONFIG_TEMPLATE: &str = include_str!("config.template.yaml");

fn host_infos_yaml<D: std::fmt::Display>(host_name: D, network: &Network, host: &Host) -> Result<()> {
    use serde_yaml::{Value, to_value};
    use std::collections::HashMap;

    if host.private_key.is_empty() {
        return Err(anyhow!("Unknown host private key"));
    }

    let mut config: Value = serde_yaml::from_str(CLIENT_CONFIG_TEMPLATE)?;

    config["pki"]["ca"] = to_value(&network.certificate)?;
    config["pki"]["cert"] = to_value(&host.certificate)?;
    config["pki"]["key"] = to_value(&host.private_key)?;

    let static_host_map: HashMap<_, _> = network.hosts.iter()
        .filter(|host| !host.external_ip.is_empty())
        .map(|host| (host.ip, vec![&host.external_ip]))
        .collect();

    config["static_host_map"] = to_value(static_host_map)?;

    config["lighthouse"]["am_lighthouse"] = to_value(host.is_lighthouse)?;
    if host.is_lighthouse {
        config["lighthouse"]["hosts"] = to_value(Vec::<String>::new())?;
    } else {
        let lighthouses: Vec<_> = network.hosts.iter().filter(|host| host.is_lighthouse).map(|host| host.ip).collect();
        config["lighthouse"]["hosts"] = to_value(lighthouses)?;
    }

    config["relay"]["am_relay"] = to_value(host.is_relay)?;

    let relays: Vec<_> = network.hosts.iter().filter(|host| host.is_relay).map(|host| host.ip).collect();
    config["relay"]["relays"] = to_value(relays)?;

    let host_file = File::create(format!("{}.yaml", host_name))?;
    serde_yaml::to_writer(host_file, &config)?;

    println!("Saved host configuration.");

    Ok(())
}

fn create_network(network_name: String, mut network: Network) -> Result<()> {
    ensure!(network.check_subnet(), "network subnet isn't in private ranges");

    let status = Command::new("nebula-cert")
        .args(["ca", "-name", &network_name])
        .status()?;

    let mut crt = String::with_capacity(512);
    std::fs::File::open("ca.crt")?.read_to_string(&mut crt)?;
    remove_file("ca.crt")?;
    let mut key = String::with_capacity(512);
    std::fs::File::open("ca.key")?.read_to_string(&mut key)?;
    remove_file("ca.key")?;

    network.certificate = crt;
    network.key = key;

    if !status.success() {
        todo!()
    }

    network.save_to_file(&network_name)?;

    Ok(())
}
