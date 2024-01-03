use config::{Config, File, FileFormat};
use std::env;

const DEFAULT_SECURE_PROFILE_PATH: &str = "/etc/krb5.conf";
const DEFAULT_PROFILE_PATH: &str = DEFAULT_SECURE_PROFILE_PATH;

#[derive(Debug)]
pub struct Profile {
    files: Vec<ProfileFile>,
}

macro_rules! get_value {
    ($fn:ident, $type:ident) => {
        pub fn $fn(&self, key: &str) -> Option<$type> {
            for file in &self.files {
                if let Ok(value) = file.config.$fn(key) {
                    return Some(value);
                }
            }
            None
        }
    };
}

impl Profile {
    pub fn new(secure: bool, kdc: bool) -> anyhow::Result<Self> {
        let mut files = Self::default_config_files(secure);
        if kdc {
            files.insert(0, Self::kdc_config_file());
        }
        let mut profile_files = vec![];
        for file in files {
            profile_files.push(ProfileFile::new(&file)?);
        }
        Ok(Self {
            files: profile_files,
        })
    }

    fn default_config_files(secure: bool) -> Vec<String> {
        let filepath = if secure {
            DEFAULT_SECURE_PROFILE_PATH.to_owned()
        } else {
            env::var("KRB5_CONFIG").unwrap_or(DEFAULT_PROFILE_PATH.to_owned())
        };
        filepath.split(':').map(|f| f.to_owned()).collect()
    }

    fn kdc_config_file() -> String {
        // TODO
        todo!("Profile::kdc_config_file")
    }

    get_value!(get_string, String);

    get_value!(get_bool, bool);

    get_value!(get_int, i64);
}

#[derive(Debug)]
struct ProfileFile {
    config: Config,
}

impl ProfileFile {
    fn new(filename: &str) -> anyhow::Result<Self> {
        let expanded_filename = match (filename.starts_with("~/"), env::var("HOME")) {
            (true, Ok(home_env)) => format!("{}{}", home_env, &filename[1..]),
            _ => filename.to_owned(),
        };
        let config = Config::builder()
            .add_source(File::with_name(&expanded_filename).format(FileFormat::Ini))
            .build()?;
        Ok(Self { config })
    }
}
