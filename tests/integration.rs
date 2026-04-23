use opaque_ke::ksf::Identity;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    CipherSuite, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialRequest, CredentialResponse,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};
use opaque_ke_hybrid::{
    client::HybridClientLogin,
    messages::{CT_LEN, EK_LEN, HybridCredentialRequest, HybridCredentialResponse},
    server::HybridServerLogin,
};

/// Minimal test cipher suite — Identity KSF so tests run fast
use opaque_ke::Ristretto255;
use opaque_ke::TripleDh;

struct TestSuite;

impl CipherSuite for TestSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = Identity;
}

/// Run a full OPAQUE registration so we have a password file for login tests
fn register(
    server_setup: &ServerSetup<TestSuite>,
    username: &[u8],
    password: &[u8],
) -> ServerRegistration<TestSuite> {
    let mut rng = OsRng;

    // Client start
    let client_start = ClientRegistration::<TestSuite>::start(&mut rng, password).unwrap();

    // Server start
    let server_start =
        ServerRegistration::<TestSuite>::start(server_setup, client_start.message, username)
            .unwrap();

    // Client finish
    let client_finish = client_start
        .state
        .finish(
            &mut rng,
            password,
            server_start.message,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();

    // Server finish
    ServerRegistration::<TestSuite>::finish(client_finish.message)
}

#[test]
fn test_hybrid_login_success() {
    let mut rng = OsRng;
    let server_setup = ServerSetup::<TestSuite>::new(&mut rng);
    let username = b"alice@example.com";
    let password = b"hunter2";

    let password_file = register(&server_setup, username, password);

    let client_start = HybridClientLogin::<TestSuite>::start(&mut rng, password).unwrap();

    // Caller serializes the opaque message where bounds are satisfied
    let opaque_ke1_bytes = client_start.opaque_message.serialize().to_vec();
    let hybrid_request =
        HybridCredentialRequest::new(opaque_ke1_bytes, *client_start.message.mlkem_ek());

    // Deserialize opaque request on server side
    let opaque_request =
        CredentialRequest::<TestSuite>::deserialize(hybrid_request.opaque_bytes()).unwrap();

    let server_start = HybridServerLogin::<TestSuite>::start(
        &mut rng,
        &server_setup,
        Some(password_file),
        opaque_request,
        hybrid_request.mlkem_ek(),
        username,
        ServerLoginParameters::default(),
    )
    .unwrap();

    // Caller serializes the opaque response
    let opaque_ke2_bytes = server_start.opaque_message.serialize().to_vec();
    let hybrid_response =
        HybridCredentialResponse::new(opaque_ke2_bytes, *server_start.message.mlkem_ct());

    let opaque_response =
        CredentialResponse::<TestSuite>::deserialize(hybrid_response.opaque_bytes()).unwrap();

    let client_finish = client_start
        .state
        .finish(
            &mut rng,
            password,
            opaque_response,
            hybrid_response.mlkem_ct(),
            ClientLoginFinishParameters::default(),
        )
        .unwrap();

    let opaque_finalization = client_finish.message;

    let server_finish = server_start
        .state
        .finish(opaque_finalization, ServerLoginParameters::default())
        .unwrap();

    assert_eq!(
        client_finish.session_key,
        server_finish.session_key,
        "client and server session keys must match"
    );
}

#[test]
fn test_hybrid_login_wrong_password() {
    let mut rng = OsRng;
    let server_setup = ServerSetup::<TestSuite>::new(&mut rng);
    let username = b"alice@example.com";

    let password_file = register(&server_setup, username, b"correct_password");

    let client_start = HybridClientLogin::<TestSuite>::start(&mut rng, b"wrong_password").unwrap();

    let opaque_ke1_bytes = client_start.opaque_message.serialize().to_vec();
    let hybrid_request =
        HybridCredentialRequest::new(opaque_ke1_bytes, *client_start.message.mlkem_ek());

    let opaque_request =
        CredentialRequest::<TestSuite>::deserialize(hybrid_request.opaque_bytes()).unwrap();

    let server_start = HybridServerLogin::<TestSuite>::start(
        &mut rng,
        &server_setup,
        Some(password_file),
        opaque_request,
        hybrid_request.mlkem_ek(),
        username,
        ServerLoginParameters::default(),
    )
    .unwrap();

    let opaque_ke2_bytes = server_start.opaque_message.serialize().to_vec();
    let hybrid_response =
        HybridCredentialResponse::new(opaque_ke2_bytes, *server_start.message.mlkem_ct());

    let opaque_response =
        CredentialResponse::<TestSuite>::deserialize(hybrid_response.opaque_bytes()).unwrap();

    // Client finish should fail with wrong password
    let result = client_start.state.finish(
        &mut rng,
        b"wrong_password",
        opaque_response,
        hybrid_response.mlkem_ct(),
        ClientLoginFinishParameters::default(),
    );

    assert!(result.is_err(), "login with wrong password must fail");
}

#[test]
fn test_message_serialization_roundtrip() {
    let opaque_bytes = vec![1u8; 64];
    let mlkem_ek = [2u8; EK_LEN];
    let mlkem_ct = [3u8; CT_LEN];

    let request = HybridCredentialRequest::new(opaque_bytes.clone(), mlkem_ek);
    let serialized = request.serialize();
    let deserialized = HybridCredentialRequest::deserialize(&serialized).unwrap();

    assert_eq!(deserialized.opaque_bytes(), opaque_bytes.as_slice());
    assert_eq!(deserialized.mlkem_ek(), &mlkem_ek);

    let response = HybridCredentialResponse::new(opaque_bytes.clone(), mlkem_ct);
    let serialized = response.serialize();
    let deserialized = HybridCredentialResponse::deserialize(&serialized).unwrap();

    assert_eq!(deserialized.opaque_bytes(), opaque_bytes.as_slice());
    assert_eq!(deserialized.mlkem_ct(), &mlkem_ct);
}

#[test]
fn test_message_deserialize_too_short() {
    let too_short = vec![0u8; EK_LEN - 1];
    assert!(HybridCredentialRequest::deserialize(&too_short).is_err());

    let too_short = vec![0u8; CT_LEN - 1];
    assert!(HybridCredentialResponse::deserialize(&too_short).is_err());
}
