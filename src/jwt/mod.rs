use super::{Reuser, Token, TokenSource, TokenJson};
use super::jws::{self, Claims, Header};
use super::hyper::Client;
use super::hyper::header::ContentType;
use super::openssl::crypto::pkey::PKey;
use super::url::form_urlencoded;
use std::io::Read;
use super::serde_json;

#[derive(Default, Clone)]
pub struct Options {
    pub email: String,
    pub private_key: Vec<u8>,
    pub private_key_id: String,
    pub subject: String,
    pub scopes: Vec<String>,
    pub token_url: String,
    pub expires: usize,
}

impl Options {
    /// return a new token source that reuses
    pub fn token_source(&self, client: Option<Client>) -> Box<TokenSource> {
        Box::new(Reuser {
            token: None,
            new: Box::new(JwtSource {
                options: self.clone(),
                client: client,
            }),
        })
    }
}

/// a token source that fetches tokens via JWT assertions
#[derive(Default)]
pub struct JwtSource {
    pub options: Options,
    pub client: Option<Client>,
}

impl TokenSource for JwtSource {
    fn token(&mut self) -> Option<Token> {
        let key = PKey::private_key_from_pem(&mut self.options.private_key.as_slice()).unwrap();
        let encoded = jws::encode(&mut Header {
                                      alg: "RS256".to_owned(),
                                      typ: "JWT".to_owned(),
                                      ..Default::default()
                                  },
                                  &mut Claims {
                                      iss: self.options.email.to_owned(),
                                      aud: self.options.token_url.to_owned(),
                                      scope: Some(self.options.scopes.join(" ")),
                                      ..Default::default()
                                  },
                                  key);
        let data = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(vec![("grant_type",
                                "urn:ietf:params:oauth:grant-type:jwt-bearer".to_owned()),
                               ("assertion", encoded)])
            .finish();
        let mut res = self.client
            .as_ref()
            .unwrap_or(&Client::new())
            .post(&self.options.token_url.clone())
            .header(ContentType::form_url_encoded())
            .body(&data)
            .send()
            .unwrap();
        let mut buf = String::new();
        res.read_to_string(&mut buf).unwrap();
        let token = serde_json::from_str::<TokenJson>(&buf).unwrap();
        Some(Token::from_token_json(&token))
    }
}
