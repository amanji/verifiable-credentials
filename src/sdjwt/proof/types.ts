import { PresentationVerificationStatus } from '../types';

export interface CredentialProofResult {
  valid: boolean;
  status: PresentationVerificationStatus;
  error?: string;
  proofIssuedAt?: number;
  warning?: boolean;
}
