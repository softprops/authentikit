extern crate hyper;
extern crate base64;
extern crate crypto;
extern crate serde_json;
extern crate serde;
extern crate openssl;
extern crate url;

use std::io::Read;
use url::{form_urlencoded, Url};
use hyper::header::ContentType;
use hyper::Client as HyperClient;
use std::ops::Add;
use std::time::{Duration, SystemTime};

pub mod jws;
pub mod jwt;

include!(concat!(env!("OUT_DIR"), "/lib.rs"));

#[derive(Debug, Clone)]
pub struct Token {
    access_token: String,
    token_type: Option<String>,
    refresh_token: Option<String>,
    expiry: Option<SystemTime>,
}

impl Token {
    pub fn authorization(&self) -> String {
        format!("{} {}", self.token_type(), self.access_token)
    }

    pub fn token_type(&self) -> String {
        if let Some(ref value) = self.token_type {
            return match value.as_ref() {
                "bearer" => "Bearer".to_owned(),
                "mac" => "MAC".to_owned(),
                "basic" => "Basic".to_owned(),
                value => value.to_owned(),
            };
        }
        "Bearer".to_owned()
    }

    fn from_token_json(json: &TokenJson) -> Token {
        Token {
            access_token: json.access_token.clone(),
            token_type: json.token_type.clone(),
            refresh_token: json.refresh_token.clone(),
            expiry: json.expires_in
                .clone()
                .map(|exp| SystemTime::now().add(Duration::new(exp as u64, 0))),
        }
    }

    /// returns true if this token has a non-empty access token that is not yet expired
    pub fn valid(&self) -> bool {
        !self.access_token.is_empty() && !self.expired()
    }

    /// returns true if this token has expred
    pub fn expired(&self) -> bool {
        self.expiry.iter()
            .filter(|exp| SystemTime::now().gt(exp))
            .count() == 0
    }
}

/// abstract contract for types which produce tokens
pub trait TokenSource {
    fn token(&mut self) -> Option<Token>;
}

/// refreshes tokens as needed
pub struct Reuser {
    pub token: Option<Token>,
    pub new: Box<TokenSource>,
}

impl TokenSource for Reuser {
    fn token(&mut self) -> Option<Token> {
        self.token.iter()
            .filter(|t| t.valid()).next().map(|t| t.clone())
            .or_else(|| {
                let next = self.new.token();
                self.token = next;
                self.token.clone()
            })
    }
}

/// refreshes tokens
pub struct Refresher {
    options: Options,
    refresh_token: String,
}

impl TokenSource for Refresher {
    fn token(&mut self) -> Option<Token> {
        let token = self.options.retrieve_token(
            vec![
                ("grant_type", "refresh_token".to_owned()),
                ("refresh_token", self.refresh_token.to_owned())
            ]
        );
        if let Some(refreshed) = token.refresh_token.clone() {
            if self.refresh_token != refreshed {
                self.refresh_token = refreshed.clone();
            }
        }
        Some(token)
    }
}

// stores a reference to endpoints required to authorize access
// and exchange grants for tokens
pub struct Endpoints {
    pub auth: Url,
    pub token: Url,
}

/// information needed for 3-legeed Oauth2 flow
pub struct Options {
    pub client_id: String,
    pub client_secret: String,
    pub endpoints: Endpoints,
    pub redirect_uri: Option<String>,
    pub scopes: Vec<String>,
    pub client: Option<HyperClient>,
}

impl Options {

    /// return a url suitable for redirecting a user agent to aquire user authorization
    pub fn auth_code_url(&self, state: Option<String>) -> Url {
        let mut query = form_urlencoded::Serializer::new(String::new());
        query.append_pair("response_type", "code")
            .append_pair("client_id", self.client_id.as_ref());
        if !self.scopes.is_empty() {
            query.append_pair("scope", self.scopes.join(" ").as_ref());
        }
        if let Some(s) = state {
            query.append_pair("state", s.as_ref());
        };
        if let Some(r) = self.redirect_uri.as_ref() {
            query.append_pair("redirect_uri", r);
        }
        let mut url = self.endpoints.auth.clone();
        url.set_query(Some(query.finish().as_ref()));
        url
    }

    /// retrieve a fresh token from token endpoint
    pub fn retrieve_token(&self, pairs: Vec<(&str, String)>) -> Token {
        let mut query = form_urlencoded::Serializer::new(String::new());
        query.append_pair("client_id", self.client_id.as_ref())
            .append_pair("client_secret", self.client_secret.as_ref());
        for (k, v) in pairs {
            query.append_pair(k, v.as_ref());
        }
        let data = query.finish();
        let mut res = self.client
            .as_ref()
            .unwrap_or(&HyperClient::new())
            .post(self.endpoints.token.clone())
            .header(ContentType::form_url_encoded())
            .body(&data)
            .send()
            .unwrap();
        let mut buf = String::new();
        res.read_to_string(&mut buf).unwrap();
        let token = serde_json::from_str::<TokenJson>(&buf).unwrap();
        Token::from_token_json(&token)
    }

    /// exchange a authorization code grant for an access token
    /// from token endpoint
    pub fn exchange(&self, code: String) -> Token {
        let mut pairs = vec![
          ("grant_type", "authorization_code".to_owned()),
          ("code", code)
        ];
        if let Some(r) = self.redirect_uri.clone() {
            pairs.push(("redirect_uri", r));
        }
        if !self.scopes.is_empty() {
            pairs.push(("scope", self.scopes.join(" ")));
        }
        self.retrieve_token(pairs)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
