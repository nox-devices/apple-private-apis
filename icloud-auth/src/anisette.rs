use crate::Error;
use omnisette::{AnisetteConfiguration, AnisetteHeaders};
use std::{collections::HashMap, time::SystemTime};

#[derive(Debug, Clone)]
pub struct AnisetteData {
    pub base_headers: HashMap<String, String>,
    pub generated_at: SystemTime,
    pub config: AnisetteConfiguration,
}

impl AnisetteData {
    /// Fetches the data at an anisette server
    pub async fn new(config: AnisetteConfiguration) -> Result<Self, crate::Error> {
        let mut b = AnisetteHeaders::get_anisette_headers_provider(config.clone())?;
        let mut base_headers = b.provider.get_authentication_headers().await?;

        base_headers.remove("X-MMe-Client-Info");

        base_headers.extend(config.extra_headers.clone());

        Ok(AnisetteData { base_headers, generated_at: SystemTime::now(), config })
    }

    pub fn needs_refresh(&self) -> bool {
        let elapsed = self.generated_at.elapsed().unwrap();
        elapsed.as_secs() > 60
    }

    pub fn is_valid(&self) -> bool {
        let elapsed = self.generated_at.elapsed().unwrap();
        elapsed.as_secs() < 90
    }

    pub async fn refresh(&self) -> Result<Self, crate::Error> {
        Self::new(self.config.clone()).await
    }

    pub fn generate_headers(
        &self,
        cpd: bool,
        twofa: bool,
    ) -> HashMap<String, String> {
        if !self.is_valid() {
            panic!("Invalid data!")
        }
        let mut headers = self.base_headers.clone();
        if twofa {
            headers.remove("X-MMe-Client-Info");
            headers.extend(self.config.extra_2fa_headers.clone());
        }

        if cpd {
            headers.insert("bootstrap".to_owned(), "true".to_owned());
            headers.insert("icscrec".to_owned(), "true".to_owned());
            headers.insert("loc".to_owned(), "en_GB".to_owned());
            headers.insert("pbe".to_owned(), "false".to_owned());
            headers.insert("prkgen".to_owned(), "true".to_owned());
            headers.insert("svct".to_owned(), "iCloud".to_owned());
        }

        headers
    }

    pub fn to_plist(&self, cpd: bool) -> plist::Dictionary {
        let mut plist = plist::Dictionary::new();
        for (key, value) in self.generate_headers(cpd, false).iter() {
            plist.insert(key.to_owned(), plist::Value::String(value.to_owned()));
        }

        plist
    }

    pub fn get_header(&self, header: &str) -> Result<String, Error> {
        let headers = self
            .generate_headers(true, false)
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
            .collect::<HashMap<String, String>>();

        match headers.get(&header.to_lowercase()) {
            Some(v) => Ok(v.to_string()),
            None => Err(Error::Parse),
        }
    }
}
