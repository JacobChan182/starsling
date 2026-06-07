// Test script to debug the JWT registration issue
import { generateKeyPair, exportJWK, calculateJwkThumbprint, importJWK } from 'jose';
import { SignJWT } from 'jose';

async function test() {
  // Generate a fresh keypair
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true
  });
  const pubJWK = await exportJWK(publicKey);
  const privJWK = await exportJWK(privateKey);
  const kid = await calculateJwkThumbprint(pubJWK, "sha256");
  pubJWK.kid = kid;
  privJWK.kid = kid;

  const hostKeypair = { publicKey: pubJWK, privateKey: privJWK };
  const agentKeypair = { publicKey: pubJWK, privateKey: privJWK }; // same for simplicity

  const alg = "EdDSA"; // CRV_TO_ALG["Ed25519"]
  const key = await importJWK(privJWK, alg);

  const hostId = kid;
  const audience = "https://intern-battleship-game-server.vercel.app/api/auth";

  const hostJWT = await new SignJWT({
    host_public_key: pubJWK,
    agent_public_key: pubJWK,
    host_name: "test-host"
  })
    .setProtectedHeader({ alg, typ: "host+jwt", kid })
    .setIssuer(hostId)
    .setSubject(hostId)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime("60s")
    .setJti(crypto.randomUUID())
    .sign(key);

  console.log("Generated JWT (first 100 chars):", hostJWT.substring(0, 100));
  
  // Decode header and payload
  const parts = hostJWT.split('.');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  console.log("Header:", JSON.stringify(header));
  console.log("Payload claims:", Object.keys(payload));
  console.log("aud:", payload.aud);

  // Try to register
  const body = {
    name: "test-agent",
    mode: "delegated",
    capabilities: ["getCompetitionRules"],
    host_name: "test-host"
  };

  const res = await fetch("https://intern-battleship-game-server.vercel.app/api/auth/agent/register", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Bearer ${hostJWT}`
    },
    body: JSON.stringify(body)
  });
  
  console.log("Status:", res.status);
  const respBody = await res.json();
  console.log("Response:", JSON.stringify(respBody));
}

test().catch(e => console.error("Error:", e.message, e.stack));
