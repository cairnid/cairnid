type CreationOptions = {
  publicKey: Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'> & {
    challenge: string;
    user: Omit<PublicKeyCredentialUserEntity, 'id'> & { id: string };
    excludeCredentials?: Array<Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string }>;
  };
};

type RequestOptions = {
  publicKey: Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & {
    challenge: string;
    allowCredentials?: Array<Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string }>;
  };
};

export async function createPasskeyCredential(options: unknown): Promise<unknown> {
  ensureWebAuthnAvailable();
  const creationOptions = options as CreationOptions;
  const publicKey = {
    ...creationOptions.publicKey,
    challenge: base64UrlToBuffer(creationOptions.publicKey.challenge),
    user: {
      ...creationOptions.publicKey.user,
      id: base64UrlToBuffer(creationOptions.publicKey.user.id)
    },
    excludeCredentials: creationOptions.publicKey.excludeCredentials?.map((credential) => ({
      ...credential,
      id: base64UrlToBuffer(credential.id)
    }))
  };

  const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!credential || !(credential.response instanceof AuthenticatorAttestationResponse)) {
    throw new Error('Passkey registration was cancelled');
  }

  return registrationCredentialToJson(credential, credential.response);
}

export async function getPasskeyCredential(options: unknown): Promise<unknown> {
  ensureWebAuthnAvailable();
  const requestOptions = options as RequestOptions;
  const publicKey = {
    ...requestOptions.publicKey,
    challenge: base64UrlToBuffer(requestOptions.publicKey.challenge),
    allowCredentials: requestOptions.publicKey.allowCredentials?.map((credential) => ({
      ...credential,
      id: base64UrlToBuffer(credential.id)
    }))
  };

  const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!credential || !(credential.response instanceof AuthenticatorAssertionResponse)) {
    throw new Error('Passkey authentication was cancelled');
  }

  return assertionCredentialToJson(credential, credential.response);
}

function registrationCredentialToJson(
  credential: PublicKeyCredential,
  response: AuthenticatorAttestationResponse
): unknown {
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToBase64Url(response.attestationObject),
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      transports: response.getTransports?.()
    },
    extensions: credential.getClientExtensionResults()
  };
}

function assertionCredentialToJson(
  credential: PublicKeyCredential,
  response: AuthenticatorAssertionResponse
): unknown {
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToBase64Url(response.authenticatorData),
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      signature: bufferToBase64Url(response.signature),
      userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : null
    },
    extensions: credential.getClientExtensionResults()
  };
}

function ensureWebAuthnAvailable() {
  if (!globalThis.PublicKeyCredential || !navigator.credentials) {
    throw new Error('Passkeys are not available in this browser');
  }
}

function base64UrlToBuffer(value: string): ArrayBuffer {
  const padded = value.padEnd(value.length + ((4 - (value.length % 4)) % 4), '=');
  const base64 = padded.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

function bufferToBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
