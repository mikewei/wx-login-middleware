use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tiny_crypto::{
    encoding::{Encoder, BASE64},
    sha1,
    sym::{Aes128, Cipher},
};

use crate::core::config::AppInfo;

const SESSION_TOKEN_TAG: u32 = 0x68686868;

#[derive(Debug, Clone)]
pub struct Error {
    err: String,
}
impl From<&str> for Error {
    fn from(err_str: &str) -> Self {
        Self {
            err: err_str.into(),
        }
    }
}
impl From<String> for Error {
    fn from(err: String) -> Self {
        Self { err }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.err)
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Default)]
pub struct ClientSession {
    pub sess_key: String,
    pub sess_token: String,
}

#[derive(Debug, Clone, Copy)]
pub struct ServerSession {
    pub session_key: [u8; 16],
    pub client_sess_key: [u8; 16],
    pub client_sess_time: SystemTime,
}

pub struct Authority<'a> {
    app_info: &'a AppInfo,
}

impl<'a> Authority<'a> {
    pub fn new(app_info: &'a AppInfo) -> Self {
        Self { app_info }
    }

    fn make_token_key(&self, openid: &str) -> [u8; 16] {
        tiny_crypto::sha1!(self.app_info.secret.0.as_bytes(), openid.as_bytes())[..16]
            .try_into()
            .unwrap()
    }

    fn make_token_iv(&self, openid: &str) -> [u8; 16] {
        tiny_crypto::sha1!(self.app_info.appid.as_bytes(), openid.as_bytes())[..16]
            .try_into()
            .unwrap()
    }

    fn make_client_sess_key(&self, session_key: &[u8; 16], seed: u32) -> [u8; 16] {
        tiny_crypto::sha1!(session_key, &bincode::serialize(&seed).unwrap())[..16]
            .try_into()
            .unwrap()
    }

    fn make_client_sess_key_str(&self, session_key: &[u8; 16], seed: u32) -> String {
        BASE64.to_text(&self.make_client_sess_key(session_key, seed))
    }

    fn make_client_sess_token_str(
        &self,
        key: &[u8; 16],
        iv: &[u8; 16],
        st: &SessionToken,
    ) -> String {
        let token_bin = bincode::serialize(st).unwrap();
        let token_enc = Aes128::from_key_array(key).encrypt_with_iv(iv, &token_bin);
        BASE64.to_text(&token_enc)
    }

    fn auth_client_sess_token_str(
        &self,
        token_str: &str,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<SessionToken, Error> {
        let token_enc = BASE64
            .from_text(token_str)
            .map_err(|e| Error::from(e.to_string()))?;
        let token_bin = Aes128::from_key_array(key).decrypt_with_iv(iv, &token_enc);
        let sess_token: SessionToken =
            bincode::deserialize(&token_bin).map_err(|e| Error::from(e.to_string()))?;
        if sess_token.tag != SESSION_TOKEN_TAG {
            return Err(Error::from(format!("bad token tag: {:#x}", sess_token.tag)));
        }
        Ok(sess_token)
    }

    pub fn make_client_session(&self, openid: &str, session_key: &[u8; 16]) -> ClientSession {
        let token_key = self.make_token_key(openid);
        let token_iv = self.make_token_iv(openid);
        let sess_token = SessionToken::new(session_key);
        ClientSession {
            sess_key: self.make_client_sess_key_str(session_key, sess_token.seed),
            sess_token: self.make_client_sess_token_str(&token_key, &token_iv, &sess_token),
        }
    }

    pub fn auth_client_session(
        &self,
        openid: &str,
        token_str: &str,
    ) -> Result<ServerSession, Error> {
        let token_key = self.make_token_key(openid);
        let token_iv = self.make_token_iv(openid);
        let sess_token = self.auth_client_sess_token_str(token_str, &token_key, &token_iv)?;
        Ok(ServerSession {
            session_key: sess_token.session_key,
            client_sess_key: self.make_client_sess_key(&sess_token.session_key, sess_token.seed),
            client_sess_time: UNIX_EPOCH + Duration::from_secs(sess_token.ts as u64),
        })
    }

    pub fn auth_client_sig(
        &self,
        skey: &str,
        url: &str,
        ts_ms_str: &str,
        nonce_str: &str,
        sig_str: &str,
        validate: impl FnOnce(Duration, u64) -> bool
    ) -> Result<(), Error> {
        let digist =
            sha1!((url.to_string() + ":" + ts_ms_str + ":" + nonce_str + ":" + skey).as_bytes());
        if hex::encode(digist) != sig_str {
            Err("bad sig value")?;
        }
        let ts_ms = ts_ms_str.parse::<u64>().map_err(|e| e.to_string())?;
        let ts = UNIX_EPOCH + Duration::from_millis(ts_ms);
        let dur = SystemTime::now()
            .duration_since(ts)
            .map_err(|e| e.to_string())?;
        let nonce = nonce_str.parse::<u64>().map_err(|e| e.to_string())?;
        if !validate(dur, nonce) {
            Err("ts or nonce is invalid")?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct SessionToken {
    seed: u32,
    ts: u32,
    session_key: [u8; 16],
    tag: u32,
}

impl SessionToken {
    fn new(session_key: &[u8; 16]) -> Self {
        Self {
            seed: fastrand::u32(..),
            ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
            session_key: *session_key,
            tag: SESSION_TOKEN_TAG,
        }
    }
}

pub mod secret_utils {
    use std::cmp::min;

    #[derive(Default, Clone)]
    pub struct SecretString(pub String);

    impl std::fmt::Debug for SecretString {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_tuple("SecretString")
                .field(&mask_string(&self.0))
                .finish()
        }
    }

    fn mask_string(origin: &str) -> String {
        let plain_len = min(origin.len() / 4, 6);
        origin
            .char_indices()
            .map(|(i, c)| if i < plain_len { c } else { '*' })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use tests::secret_utils::SecretString;

    use super::*;

    #[test]
    fn make_and_auth() {
        let app_info = AppInfo {
            appid: "some_appid".into(),
            secret: SecretString("some_secret".into()),
        };
        let openid = "some-openid";
        let auth = Authority::new(&app_info);
        let session_key: [u8; 16] = BASE64
            .from_text("HyVFkGl5F5OQWJZZaNzBBg==")
            .unwrap()
            .try_into()
            .unwrap();
        let client_sess = auth.make_client_session(openid, &session_key);
        println!("client_sess: {:?}", client_sess);
        let server_sess = auth
            .auth_client_session(openid, &client_sess.sess_token)
            .unwrap();
        println!("server_sess: {:?}", server_sess);
        assert_eq!(
            client_sess.sess_key,
            BASE64.to_text(&server_sess.client_sess_key)
        );
    }
    #[test]
    fn secret_string() {
        use secret_utils::SecretString;
        let sec_str = SecretString("abcdefgh1234567890".into());
        assert_eq!(
            format!("{:?}", sec_str),
            "SecretString(\"abcd**************\")"
        );
    }
}
