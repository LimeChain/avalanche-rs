use std::fs::File;
use std::net::IpAddr;
use std::path::Path;
use serde::{Deserialize, Deserializer};

const BOOTSTRAPPERS_FILE_PATH: &str = "genesis/bootstrappers.json";
#[derive(Debug)]
pub struct Bootstrapper {
    pub id: String,
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct Bootstrappers {
    pub mainnet: Vec<Bootstrapper>,
    pub fuji: Vec<Bootstrapper>,
}

impl<'de> Deserialize<'de> for Bootstrapper {
    fn deserialize<D>(deserializer: D) -> Result<Bootstrapper, D::Error>
        where
            D: Deserializer<'de>,
    {
        #[derive(Debug, Deserialize)]
        struct BootstrapperFields {
            id: String,
            ip: String,
        }

        let fields: BootstrapperFields = Deserialize::deserialize(deserializer)?;

        // Split the IP address and port
        let ip_parts: Vec<&str> = fields.ip.split(':').collect();
        if ip_parts.len() != 2 {
            return Err(serde::de::Error::custom("Invalid IP address format"));
        }

        // Parse the IP address
        let ip = ip_parts[0].parse::<IpAddr>().map_err(serde::de::Error::custom)?;

        // Parse the port
        let port = ip_parts[1].parse::<u16>().map_err(serde::de::Error::custom)?;

        Ok(Bootstrapper {
            id: fields.id,
            ip,
            port,
        })
    }
}

pub fn read_boostrap_json() -> Bootstrappers {
    let json_file_path = Path::new(BOOTSTRAPPERS_FILE_PATH);
    let file = File::open(json_file_path)
        .expect("Bootstrapper file not found");

    let parsed: Bootstrappers = serde_json::from_reader(file)
        .expect("Error while parsing Bootstrapper file");

    parsed
}