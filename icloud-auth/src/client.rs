use std::{collections::HashMap, str::FromStr, sync::Arc};

// use crate::anisette::AnisetteData;
use crate::{anisette::AnisetteData, Error};
use aes::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use omnisette::{AnisetteClient, AnisetteProvider, ArcAnisetteClient, LoginClientInfo};
use plist::{Dictionary, Value};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue}, Certificate, Client, ClientBuilder, Proxy, Response
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use srp::{
    client::{SrpClient, SrpClientVerifier},
    groups::G_2048,
};
use tokio::sync::Mutex;
use uuid::Uuid;

const GSA_ENDPOINT: &str = "https://gsa.apple.com/grandslam/GsService2";
const APPLE_ROOT: &[u8] = include_bytes!("./apple_root.der");

#[derive(Debug, Serialize, Deserialize)]
pub struct InitRequestBody {
    #[serde(rename = "A2k")]
    a_pub: plist::Value,
    cpd: plist::Dictionary,
    #[serde(rename = "o")]
    operation: String,
    ps: Vec<String>,
    #[serde(rename = "u")]
    username: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RequestHeader {
    #[serde(rename = "Version")]
    version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitRequest {
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: InitRequestBody,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequestBody {
    #[serde(rename = "M1")]
    m: plist::Value,
    cpd: plist::Dictionary,
    c: String,
    #[serde(rename = "o")]
    operation: String,
    #[serde(rename = "u")]
    username: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: ChallengeRequestBody,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthTokenRequestBody {
    app: Vec<String>,
    c: plist::Value,
    cpd: plist::Dictionary,
    #[serde(rename = "o")]
    operation: String,
    t: String,
    u: String,
    checksum: plist::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthTokenRequest {
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: AuthTokenRequestBody,
}

pub struct AppleAccount<T: AnisetteProvider> {
    //TODO: move this to omnisette
    pub anisette: ArcAnisetteClient<T>,
    pub client_info: LoginClientInfo,
    // pub spd:  Option<plist::Dictionary>,
    //mutable spd
    pub spd: Option<plist::Dictionary>,
    pub username: Option<String>,
    client: Client,
    pub tokens: HashMap<String, String>,
}

#[derive(Clone)]
pub struct AppToken {
    pub app_tokens: plist::Dictionary,
    pub auth_token: String,
    pub app: String,
}
//Just make it return a custom enum, with LoggedIn(account: AppleAccount) or Needs2FA(FinishLoginDel: fn(i32) -> TFAResponse)
#[repr(C)]
#[derive(Debug)]
pub enum LoginState {
    LoggedIn,
    // NeedsSMS2FASent(Send2FAToDevices),
    NeedsDevice2FA,
    Needs2FAVerification,
    NeedsSMS2FA,
    NeedsSMS2FAVerification(VerifyBody),
    NeedsExtraStep(String),
    NeedsLogin,
}

#[derive(Serialize, Debug, Clone)]
struct VerifyCode {
    code: String,
}

#[derive(Serialize, Debug, Clone)]
#[repr(C)]
struct PhoneNumber {
    id: u32
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[repr(C)]
pub struct VerifyBody {
    phone_number: PhoneNumber,
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_code: Option<VerifyCode>
}

#[repr(C)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedPhoneNumber {
    pub number_with_dial_code: String,
    pub last_two_digits: String,
    pub push_mode: String,
    pub id: u32
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtras {
    pub trusted_phone_numbers: Vec<TrustedPhoneNumber>,
    pub recovery_url: Option<String>,
    pub cant_use_phone_number_url: Option<String>,
    pub dont_have_access_url: Option<String>,
    pub recovery_web_url: Option<String>,
    pub repair_phone_number_url: Option<String>,
    pub repair_phone_number_web_url: Option<String>,
    #[serde(skip)]
    pub new_state: Option<LoginState>,
}

// impl Send2FAToDevices {
//     pub fn send_2fa_to_devices(&self) -> LoginResponse {
//         self.account.send_2fa_to_devices().unwrap()
//     }
// }

// impl Verify2FA {
//     pub fn verify_2fa(&self, tfa_code: &str) -> LoginResponse {
//         self.account.verify_2fa(&tfa_code).unwrap()
//     }
// }

async fn parse_response(res: Result<Response, reqwest::Error>) -> Result<plist::Dictionary, crate::Error> {
    let res = res?.text().await?;
    let res: plist::Dictionary = plist::from_bytes(res.as_bytes())?;
    let res: plist::Value = res.get("Response").unwrap().to_owned();
    match res {
        plist::Value::Dictionary(dict) => Ok(dict),
        _ => Err(crate::Error::Parse),
    }
}

impl<T: AnisetteProvider> AppleAccount<T> {

    pub fn new_with_anisette(client_info: LoginClientInfo, anisette:  ArcAnisetteClient<T>) -> Result<Self, crate::Error> {
        let client = ClientBuilder::new()
            .cookie_store(true)
            .add_root_certificate(Certificate::from_der(APPLE_ROOT)?)
            // .proxy(Proxy::https("https://192.168.86.25:8080").unwrap())
            // .danger_accept_invalid_certs(true)
            .http1_title_case_headers()
            .connection_verbose(true)
            .build()?;

        Ok(AppleAccount {
            client,
            anisette,
            client_info,
            spd: None,
            username: None,
            tokens: HashMap::new(),
        })
    }

    pub async fn login(
        appleid_closure: impl Fn() -> (String, String),
        tfa_closure: impl Fn() -> String,
        client_info: LoginClientInfo,
        anisette: ArcAnisetteClient<T>
    ) -> Result<AppleAccount<T>, Error> {
        AppleAccount::login_with_anisette(appleid_closure, tfa_closure, client_info, anisette).await
    }

    pub async fn get_anisette(&self) -> Result<AnisetteData, crate::Error> {
        let mut locked = self.anisette.lock().await;
        Ok(AnisetteData::new(&mut *locked, self.client_info.clone()).await?)
    }

    fn create_checksum(session_key: &Vec<u8>, dsid: &str, app_name: &str) -> Vec<u8> {
        Hmac::<Sha256>::new_from_slice(&session_key)
            .unwrap()
            .chain_update("apptokens".as_bytes())
            .chain_update(dsid.as_bytes())
            .chain_update(app_name.as_bytes())
            .finalize()
            .into_bytes()
            .to_vec()
    }

    /// # Arguments
    ///
    /// * `appleid_closure` - A closure that takes no arguments and returns a tuple of the Apple ID and password
    /// * `tfa_closure` - A closure that takes no arguments and returns the 2FA code
    /// * `anisette` - AnisetteData
    /// # Examples
    ///
    /// ```
    /// use icloud_auth::AppleAccount;
    /// use omnisette::AnisetteData;
    ///
    /// let anisette = AnisetteData::new();
    /// let account = AppleAccount::login(
    ///   || ("test@waffle.me", "password")
    ///   || "123123",
    ///  anisette
    /// );
    /// ```
    /// Note: You would not provide the 2FA code like this, you would have to actually ask input for it.
    //TODO: add login_with_anisette and login, where login autodetcts anisette
    pub async fn login_with_anisette<F: Fn() -> (String, String), G: Fn() -> String>(
        appleid_closure: F,
        tfa_closure: G,
        client_info: LoginClientInfo,
        anisette: ArcAnisetteClient<T>
    ) -> Result<AppleAccount<T>, Error> {
        let mut _self = AppleAccount::new_with_anisette(client_info, anisette)?;
        let (username, password) = appleid_closure();
        let mut response = _self.login_email_pass(&username, &password).await?;
        loop {
            match response {
                // LoginState::NeedsDevice2FA => response = _self.send_2fa_to_devices().await?,
                LoginState::Needs2FAVerification => {
                    response = _self.verify_2fa(tfa_closure()).await?
                }
                LoginState::NeedsSMS2FA | LoginState::NeedsDevice2FA => {
                    _self.send_2fa_to_devices().await?;
                    response = _self.send_sms_2fa_to_devices(1).await?
                }
                LoginState::NeedsSMS2FAVerification(body) => {
                    response = _self.verify_sms_2fa(tfa_closure(), body).await?
                }
                LoginState::NeedsLogin => {
                    response = _self.login_email_pass(&username, &password).await?
                }
                LoginState::LoggedIn => return Ok(_self),
                LoginState::NeedsExtraStep(step) => {
                    if _self.get_pet().is_some() {
                        return Ok(_self)
                    } else {
                        return Err(Error::ExtraStep(step))
                    }
                }
            }
        }
    }

    pub fn get_pet(&self) -> Option<String> {
        self.tokens.get("com.apple.gs.idms.pet").cloned()
    }

    pub fn get_name(&self) -> (String, String) {
        (
            self.spd.as_ref().unwrap().get("fn").unwrap().as_string().unwrap().to_string(),
            self.spd.as_ref().unwrap().get("ln").unwrap().as_string().unwrap().to_string()
        )
    }

    pub async fn login_email_pass(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<LoginState, Error> {
        let srp_client = SrpClient::<Sha256>::new(&G_2048);
        let a: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let a_pub = srp_client.compute_public_ephemeral(&a);

        self.username = Some(username.to_string());

        let valid_anisette = self.get_anisette().await?;

        let mut gsa_headers = HeaderMap::new();
        gsa_headers.insert(
            "Content-Type",
            HeaderValue::from_str("text/x-xml-plist").unwrap(),
        );
        gsa_headers.insert("Accept", HeaderValue::from_str("*/*").unwrap());
        gsa_headers.extend(valid_anisette.get_gsservice_headers().into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), HeaderValue::from_str(&b).unwrap())));

        let request_id = Uuid::new_v4().to_string().to_uppercase();

        let header = RequestHeader {
            version: "1.0.1".to_string(),
        };
        let body = InitRequestBody {
            a_pub: plist::Value::Data(a_pub),
            cpd: valid_anisette.get_cpd_data(&request_id),
            operation: "init".to_string(),
            ps: vec!["s2k".to_string(), "s2k_fo".to_string()],
            username: username.to_string(),
        };

        let packet = InitRequest {
            header: header.clone(),
            request: body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &packet)?;
        let buffer = String::from_utf8(buffer).unwrap();

        // println!("{:?}", gsa_headers.clone());
        // println!("{:?}", buffer);

        let res = self
            .client
            .post(GSA_ENDPOINT)
            .headers(gsa_headers.clone())
            .body(buffer)
            .send().await;

        let res = parse_response(res).await?;
        let err_check = Self::check_error(&res);
        if err_check.is_err() {
            return Err(err_check.err().unwrap());
        }
        // println!("{:?}", res);
        let salt = res.get("s").unwrap().as_data().unwrap();
        let b_pub = res.get("B").unwrap().as_data().unwrap();
        let iters = res.get("i").unwrap().as_signed_integer().unwrap();
        let c = res.get("c").unwrap().as_string().unwrap();

        let mut password_hasher = sha2::Sha256::new();
        password_hasher.update(&password.as_bytes());
        let hashed_password = password_hasher.finalize();

        let mut password_buf = [0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(
            &hashed_password,
            salt,
            iters as u32,
            &mut password_buf,
        );

        let verifier: SrpClientVerifier<Sha256> = srp_client
            .process_reply(&a, &username.as_bytes(), &password_buf, salt, b_pub)
            .unwrap();

        let m = verifier.proof();

        let body = ChallengeRequestBody {
            m: plist::Value::Data(m.to_vec()),
            c: c.to_string(),
            cpd: valid_anisette.get_cpd_data(&request_id),
            operation: "complete".to_string(),
            username: username.to_string(),
        };

        let packet = ChallengeRequest {
            header,
            request: body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &packet)?;
        let buffer = String::from_utf8(buffer).unwrap();

        let res = self
            .client
            .post(GSA_ENDPOINT)
            .headers(gsa_headers.clone())
            .body(buffer)
            .send().await;

        let res = parse_response(res).await?;
        let err_check = Self::check_error(&res);
        if err_check.is_err() {
            return Err(err_check.err().unwrap());
        }
        // println!("{:?}", res);
        let m2 = res.get("M2").unwrap().as_data().unwrap();
        verifier.verify_server(&m2).unwrap();

        let spd = res.get("spd").unwrap().as_data().unwrap();
        let decrypted_spd = Self::decrypt_cbc(&verifier, spd);
        let decoded_spd: plist::Dictionary = plist::from_bytes(&decrypted_spd).unwrap();

        let status = res.get("Status").unwrap().as_dictionary().unwrap();

        if let Some(Value::Dictionary(dict)) = decoded_spd.get("t") {
            let keys: HashMap<String, String> = dict.iter().filter_map(|(service, value)| {
                Some((service.clone(), value.as_dictionary()?.get("token")?.as_string()?.to_string()))
            }).collect();
            self.tokens = keys;
        }
        println!("spd {:?}", decoded_spd);

        self.spd = Some(decoded_spd);

        if let Some(plist::Value::String(s)) = status.get("au") {
            return match s.as_str() {
                "trustedDeviceSecondaryAuth" => Ok(LoginState::NeedsDevice2FA),
                "secondaryAuth" => Ok(LoginState::NeedsSMS2FA),
                _unk => Ok(LoginState::NeedsExtraStep(_unk.to_string()))
            }
        }

        Ok(LoginState::LoggedIn)
    }

    fn create_session_key(usr: &SrpClientVerifier<Sha256>, name: &str) -> Vec<u8> {
        Hmac::<Sha256>::new_from_slice(&usr.key())
            .unwrap()
            .chain_update(name.as_bytes())
            .finalize()
            .into_bytes()
            .to_vec()
    }

    fn decrypt_cbc(usr: &SrpClientVerifier<Sha256>, data: &[u8]) -> Vec<u8> {
        let extra_data_key = Self::create_session_key(usr, "extra data key:");
        let extra_data_iv = Self::create_session_key(usr, "extra data iv:");
        let extra_data_iv = &extra_data_iv[..16];

        cbc::Decryptor::<aes::Aes256>::new_from_slices(&extra_data_key, extra_data_iv)
            .unwrap()
            .decrypt_padded_vec_mut::<Pkcs7>(&data)
            .unwrap()
    }

    pub async fn send_2fa_to_devices(&self) -> Result<LoginState, crate::Error> {
        let headers = self.build_2fa_headers(false);

        let res = self
            .client
            .get("https://gsa.apple.com/auth/verify/trusteddevice")
            .headers(headers.await?)
            .send().await?;

        if !res.status().is_success() {
            return Err(Error::AuthSrp);
        }

        return Ok(LoginState::Needs2FAVerification);
    }

    pub async fn send_sms_2fa_to_devices(&self, phone_id: u32) -> Result<LoginState, crate::Error> {
        let headers = self.build_2fa_headers(true);


        let body = VerifyBody {
            phone_number: PhoneNumber {
                id: phone_id
            },
            mode: "sms".to_string(),
            security_code: None
        };

        let res = self
            .client
            .put("https://gsa.apple.com/auth/verify/phone/")
            .headers(headers.await?)
            .header("Accept", "application/json")
            .json(&body)
            .send().await?;

        if !res.status().is_success() {
            return Err(Error::AuthSrp);
        }

        return Ok(LoginState::NeedsSMS2FAVerification(body));
    }

    pub async fn get_auth_extras(&self) -> Result<AuthenticationExtras, Error> {
        let headers = self.build_2fa_headers(true);

        let req = self.client
            .get("https://gsa.apple.com/auth")
            .headers(headers.await?)
            .header("Accept", "application/json")
            .send().await?;
        let status = req.status().as_u16();
        let mut new_state = req.json::<AuthenticationExtras>().await?;
        if status == 201 {
            new_state.new_state = Some(LoginState::NeedsSMS2FAVerification(VerifyBody {
                phone_number: PhoneNumber {
                    id: new_state.trusted_phone_numbers.first().unwrap().id
                },
                mode: "sms".to_string(),
                security_code: None
            }));
        }

        Ok(new_state)
    }

    pub async fn request_update_account(&self) -> Result<String, Error> {
        let mut map = HashMap::new();
        let adsid = self.spd.as_ref().unwrap()["adsid"].as_string().unwrap().to_string();
        let base_headers = self.anisette.lock().await.get_headers().await?.clone();
        map.extend(base_headers);

        map.extend([
            ("Authorization", format!("Basic {}", base64::encode(format!("{}:{}", self.username.as_ref().unwrap().trim(), self.get_pet().expect("No pet?"))))),
            ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)".to_string()),
            ("X-Apple-ADSID", adsid.clone()),
            ("X-Apple-GS-Token", base64::encode(format!("{}:{}", adsid, self.tokens["com.apple.gs.icloud.family.auth"]))),
            ("X-Apple-I-Current-Application", "com.apple.systempreferences.AppleIDSettings".to_string()),
            ("X-Apple-I-Current-Application-Version", "1".to_string()),
            ("X-MMe-Client-Info", self.client_info.update_account_bundle_id.clone()),
            ("X-MMe-Country", "US".to_string()),
            ("X-MMe-Language", "en,en-US".to_string()),
            ("x-apple-i-device-type", "1".to_string()),
        ].into_iter().map(|(a, b)| (a.to_string(), b)));

        let header_map = HeaderMap::from_iter(map.into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())));

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &Dictionary::new())?;

        let text = self.client.post("https://setup.icloud.com/setup/update_account_ui")
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Accept-Encoding", "gzip, deflate, br")
            .header("Accept-Language", "en-US,en")
            .header("Content-Type", "text/plist")
            .header("Origin", "null")
            .header("Sec-Fetch-Dest", "document")
            .header("Sec-Fetch-Mode", "navigate")
            .header("Sec-Fetch-Site", "cross-site")
            .headers(header_map)
            .body(buffer)
            .send().await?
            .text().await?;

        Ok(text)
    }

    pub async fn verify_2fa(&mut self, code: String) -> Result<LoginState, Error> {
        let headers = self.build_2fa_headers(false);
        // println!("Recieved code: {}", code);
        let res = self
            .client
            .get("https://gsa.apple.com/grandslam/GsService2/validate")
            .headers(headers.await?)
            .header(
                HeaderName::from_str("security-code").unwrap(),
                HeaderValue::from_str(&code).unwrap(),
            )
            .send().await?;

        let headers = res.headers().clone();

        let res: plist::Dictionary =
            plist::from_bytes(res.text().await?.as_bytes())?;

        Self::check_error(&res)?;

        self.tokens = headers.get_all("X-Apple-GS-Token").iter().map(|header| {
            let decoded = String::from_utf8(base64::decode(&header.as_bytes()).expect("Not base64!")).expect("Decoded not utf8!");
            let parts = decoded.split(":").collect::<Vec<&str>>();
            (parts[0].to_string(), parts[1].to_string())
        }).collect();

        if let Some(pet) = headers.get("X-Apple-PE-Token") {
            self.parse_pet_header(pet.to_str().unwrap());
            return Ok(LoginState::LoggedIn);
        }

        Ok(LoginState::NeedsLogin)
    }

    pub async fn verify_sms_2fa(&mut self, code: String, mut body: VerifyBody) -> Result<LoginState, Error> {
        let headers = self.build_2fa_headers(true).await?;
        // println!("Recieved code: {}", code);

        body.security_code = Some(VerifyCode { code });

        let res = self
            .client
            .post("https://gsa.apple.com/auth/verify/phone/securitycode")
            .headers(headers)
            .header("accept", "application/json")
            .json(&body)
            .send().await?;

        if res.status() != 200 {
            return Err(Error::Bad2faCode);
        }

        self.tokens = res.headers().get_all("X-Apple-GS-Token").iter().map(|header| {
            let decoded = String::from_utf8(base64::decode(&header.as_bytes()).expect("Not base64!")).expect("Decoded not utf8!");
            let parts = decoded.split(":").collect::<Vec<&str>>();
            (parts[0].to_string(), parts[1].to_string())
        }).collect();

        if let Some(pet) = res.headers().get("X-Apple-PE-Token") {
            self.parse_pet_header(pet.to_str().unwrap());
            return Ok(LoginState::LoggedIn);
        }

        Ok(LoginState::NeedsLogin)
    }

    fn parse_pet_header(&mut self, data: &str) {
        let decoded = String::from_utf8(base64::decode(data).unwrap()).unwrap();
        self.tokens.insert("com.apple.gs.idms.pet".to_string(), decoded.split(":").nth(1).unwrap().to_string());
    }

    fn check_error(res: &plist::Dictionary) -> Result<(), Error> {
        let res = match res.get("Status") {
            Some(plist::Value::Dictionary(d)) => d,
            _ => &res,
        };

        if res.get("ec").unwrap().as_signed_integer().unwrap() != 0 {
            return Err(Error::AuthSrpWithMessage(
                res.get("ec").unwrap().as_signed_integer().unwrap(),
                res.get("em").unwrap().as_string().unwrap().to_owned(),
            ));
        }

        Ok(())
    }

    // pub async 

    pub async fn build_2fa_headers(&self, sms: bool) -> Result<HeaderMap, crate::Error> {
        let spd = self.spd.as_ref().unwrap();
        let dsid = spd.get("adsid").unwrap().as_string().unwrap();
        let token = spd.get("GsIdmsToken").unwrap().as_string().unwrap();

        let identity_token = base64::encode(format!("{}:{}", dsid, token));

        let valid_anisette = self.get_anisette().await?;

        let mut headers = HeaderMap::new();
        valid_anisette
            .get_extra_headers()
            .iter()
            .for_each(|(k, v)| {
                headers.append(
                    HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    HeaderValue::from_str(v).unwrap(),
                );
            });

        if !sms {
            headers.insert(
                "Content-Type",
                HeaderValue::from_str("text/x-xml-plist").unwrap(),
            );
            headers.insert("Accept", HeaderValue::from_str("text/x-xml-plist").unwrap());
        }
        // headers.insert("User-Agent", HeaderValue::from_str("Xcode").unwrap());
        headers.append(
            "X-Apple-Identity-Token",
            HeaderValue::from_str(&identity_token).unwrap(),
        );


        Ok(headers)
    }
}
