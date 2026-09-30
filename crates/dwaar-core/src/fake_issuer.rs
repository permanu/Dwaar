// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Connect the fake ACME issuer to the challenge Dwaar is serving.

use dwaar_tls::acme::fake::HttpChallenge;

use crate::permanu_challenge::{CHALLENGE_PREFIX, PermanuChallenges};

impl HttpChallenge for PermanuChallenges {
    fn served_body(&self, host: &str, token: &str) -> Option<Vec<u8>> {
        let path = format!("{CHALLENGE_PREFIX}{token}");
        let reply = self.reply(Some(host), "GET", &path)?;
        if reply.status == 200 {
            Some(reply.body)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::path::Path;
    use std::sync::Arc;

    use dwaar_tls::acme::fake::{FakeDns, FakeIssueError, FakeIssuer};
    use dwaar_tls::cert_store::CertStore;
    use openssl::nid::Nid;
    use openssl::x509::X509NameRef;

    use crate::permanu_challenge::PermanuChallenges;

    const TOKEN: &str = "perm_7f3a";
    const NAME: &str = "app.example.com";

    fn ipv4(text: &str) -> IpAddr {
        text.parse().expect("ipv4")
    }

    fn assert_no_certificate(root: &Path, store: &CertStore, domain: &str) {
        assert!(
            store.get(domain).is_none(),
            "cert store has a certificate for {domain}"
        );
        if !root.exists() {
            return;
        }
        let mut pending = vec![root.to_path_buf()];
        while let Some(dir) = pending.pop() {
            let entries = std::fs::read_dir(&dir).expect("read dir");
            for entry in entries {
                let entry = entry.expect("dir entry");
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                let name = entry.file_name();
                let name = name.to_string_lossy();
                assert!(
                    !name.ends_with(".pem") && !name.ends_with(".key"),
                    "certificate stored at {}",
                    path.display()
                );
            }
        }
    }

    fn org_values(name: &X509NameRef) -> Vec<String> {
        name.entries_by_nid(Nid::ORGANIZATIONNAME)
            .filter_map(|entry| entry.data().as_utf8().ok().map(|text| text.to_string()))
            .collect()
    }

    #[tokio::test]
    async fn issues_when_dns_matches_and_dwaar_serves_the_token() {
        let ip = ipv4("203.0.113.10");
        let challenges = Arc::new(PermanuChallenges::new());
        challenges.register(ip, TOKEN).expect("register");

        let mut dns = FakeDns::new();
        dns.insert("App.Example.com", ip);

        let root = tempfile::tempdir().expect("tempdir");
        let issuer = FakeIssuer::new(dns, Arc::clone(&challenges), root.path().join("certs"));

        issuer
            .issue("App.Example.com", ip, TOKEN)
            .await
            .expect("certificate issued");

        let cert_path = root.path().join("certs").join("app.example.com.pem");
        let key_path = root.path().join("certs").join("app.example.com.key");
        assert!(cert_path.is_file(), "cert file missing");
        assert!(key_path.is_file(), "key file missing");

        let cached = issuer
            .cert_store()
            .get("app.example.com")
            .expect("cert store loads the issued certificate");
        let sans = cached.cert.subject_alt_names().expect("subject alt names");
        assert!(
            sans.iter().any(|san| san.dnsname() == Some(NAME)),
            "certificate is not for {NAME}"
        );
        let pubkey = cached.cert.public_key().expect("public key");
        cached
            .cert
            .verify(&pubkey)
            .expect("certificate must be self-signed by the fake issuer");
        assert!(
            cached.key.public_eq(&pubkey),
            "stored key does not match the certificate"
        );
        assert_eq!(
            org_values(cached.cert.issuer_name()),
            ["Permanu Fake Issuer"]
        );
        assert_eq!(
            org_values(cached.cert.subject_name()),
            ["Permanu Fake Issuer"]
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path)
                .expect("key metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
            let dir_mode = std::fs::metadata(issuer.cert_dir())
                .expect("cert dir metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
        }

        let mut names: Vec<String> = std::fs::read_dir(issuer.cert_dir())
            .expect("cert dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "app.example.com.key".to_owned(),
                "app.example.com.pem".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn issues_for_ipv6_when_dns_matches_and_dwaar_serves_the_token() {
        let ip: IpAddr = "2001:db8::10".parse().expect("ipv6");
        let challenges = Arc::new(PermanuChallenges::new());
        challenges.register(ip, TOKEN).expect("register");

        let mut dns = FakeDns::new();
        dns.insert("v6.example.com", ip);

        let root = tempfile::tempdir().expect("tempdir");
        let issuer = FakeIssuer::new(dns, challenges, root.path().join("certs"));
        issuer
            .issue("v6.example.com", ip, TOKEN)
            .await
            .expect("certificate issued");

        let cached = issuer
            .cert_store()
            .get("v6.example.com")
            .expect("stored ipv6 name");
        let sans = cached.cert.subject_alt_names().expect("san");
        assert!(
            sans.iter()
                .any(|san| san.dnsname() == Some("v6.example.com"))
        );
    }

    #[tokio::test]
    async fn fails_closed_when_dns_proof_is_wrong() {
        let ip = ipv4("203.0.113.10");
        let other = ipv4("198.51.100.20");
        let challenges = Arc::new(PermanuChallenges::new());
        challenges.register(ip, TOKEN).expect("register");

        let mut dns = FakeDns::new();
        dns.insert(NAME, other);

        let root = tempfile::tempdir().expect("tempdir");
        let issuer = FakeIssuer::new(dns, Arc::clone(&challenges), root.path().join("certs"));

        let wrong_address = issuer
            .issue(NAME, ip, TOKEN)
            .await
            .expect_err("dns mismatch");
        assert!(matches!(
            wrong_address,
            FakeIssueError::DnsMismatch { ref domain } if domain == NAME
        ));
        assert_no_certificate(root.path(), issuer.cert_store(), NAME);

        let absent = issuer
            .issue("missing.example.com", ip, TOKEN)
            .await
            .expect_err("missing name");
        assert!(matches!(absent, FakeIssueError::DnsMismatch { .. }));
        assert_no_certificate(root.path(), issuer.cert_store(), "missing.example.com");
        assert_no_certificate(root.path(), issuer.cert_store(), NAME);
    }

    #[tokio::test]
    async fn fails_closed_when_challenge_token_is_wrong() {
        let ip = ipv4("203.0.113.10");
        let other = ipv4("198.51.100.20");
        let challenges = Arc::new(PermanuChallenges::new());
        challenges.register(ip, TOKEN).expect("register");
        challenges
            .register(other, "other_token")
            .expect("register other");

        let mut dns = FakeDns::new();
        dns.insert(NAME, ip);

        let root = tempfile::tempdir().expect("tempdir");
        let issuer = FakeIssuer::new(dns, Arc::clone(&challenges), root.path().join("certs"));

        let wrong_token = issuer
            .issue(NAME, ip, "not-the-token")
            .await
            .expect_err("wrong token");
        assert!(matches!(
            wrong_token,
            FakeIssueError::ChallengeMismatch { ref domain } if domain == NAME
        ));
        assert_no_certificate(root.path(), issuer.cert_store(), NAME);

        let other_ip = issuer
            .issue(NAME, ip, "other_token")
            .await
            .expect_err("token is served for a different address");
        assert!(matches!(other_ip, FakeIssueError::ChallengeMismatch { .. }));
        assert_no_certificate(root.path(), issuer.cert_store(), NAME);

        let bare = Arc::new(PermanuChallenges::new());
        let mut dns = FakeDns::new();
        dns.insert(NAME, ip);
        let unset = FakeIssuer::new(dns, bare, root.path().join("certs-unset"));
        let err = unset
            .issue(NAME, ip, TOKEN)
            .await
            .expect_err("nothing served");
        assert!(matches!(err, FakeIssueError::ChallengeMismatch { .. }));
        assert_no_certificate(root.path(), unset.cert_store(), NAME);
    }

    #[tokio::test]
    async fn does_not_store_a_certificate_for_an_unsafe_name() {
        let ip = ipv4("203.0.113.10");
        let challenges = Arc::new(PermanuChallenges::new());
        challenges.register(ip, TOKEN).expect("register");

        let mut dns = FakeDns::new();
        dns.insert("../evil", ip);

        let root = tempfile::tempdir().expect("tempdir");
        let issuer = FakeIssuer::new(dns, challenges, root.path().join("certs"));
        let err = issuer
            .issue("../evil", ip, TOKEN)
            .await
            .expect_err("unsafe name");
        assert!(matches!(err, FakeIssueError::NotStored { .. }));
        assert!(!root.path().join("evil.pem").exists());
        assert!(!root.path().join("evil.key").exists());
        assert_no_certificate(root.path(), issuer.cert_store(), "evil");
    }
}
