import { generateSignedPayload } from './crypt';

export default async function diu(offerId: string) {
  return generateSignedPayload(offerId);
}
