// Simulate what the server does: extract host_public_key from JWT payload and verify the JWT
import { generateKeyPair, exportJWK, calculateJwkThumbprint, importJWK, SignJWT, jwtVerify } from 'jose';

async function test() {
  // Generate a fresh keypair (simulating CLI)
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true
  });
  const pubJWK = await exportJWK(publicKey);
  const privJWK = await exportJWK(privateKey);
  const kid = await calculateJwkThumbprint(pubJWK, "sha256");
  pubJWK.kid = kid;
  privJWK.kid = kid;

  const alg = "EdDSA";
  const key = await importJWK(privJWK, alg);
  const aud = "https://intern-battleship-game-server.vercel.app/api/auth";

  const jwt = await new SignJWT({
    host_public_key: pubJWK,
    agent_public_key: pubJWK,
    host_name: "test"
  })
    .setProtectedHeader({ alg, typ: "host+jwt", kid })
    .setIssuer(kid)
    .setSubject(kid)
    .setAudience(aud)
    .setIssuedAt()
    .setExpirationTime("60s")
    .setJti(crypto.randomUUID())
    .sign(key);

  console.log("JWT header:", JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url')));
  console.log("JWT payload keys:", Object.keys(JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url'))));

  // Simulate server-side: extract host_public_key from payload and verify
  const rawPayload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url'));
  const hostInlinePubKey = rawPayload.host_public_key;
  console.log("hostInlinePubKey:", JSON.stringify(hostInlinePubKey));

  // resolveAlgorithm(hostInlinePubKey) - Ed25519 → EdDSA
  const verifyAlg = hostInlinePubKey.crv ? {Ed25519: "EdDSA", Ed448: "EdDSA"}[hostInlinePubKey.crv] || "EdDSA" : "EdDSA";
  console.log("verifyAlg:", verifyAlg);

  const verifyKey = await importJWK(hostInlinePubKey, verifyAlg);
  
  try {
    const { payload } = await jwtVerify(jwt, verifyKey, {
      maxTokenAge: "60s",
      algorithms: [verifyAlg]
    });
    console.log("LOCAL VERIFICATION: SUCCESS", payload.aud);
  } catch (e) {
    console.error("LOCAL VERIFICATION FAILED:", e.message);
  }
}

test().catch(e => console.error("Error:", e.message));
