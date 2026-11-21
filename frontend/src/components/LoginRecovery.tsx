const MESSAGES: Record<string, string> = {
  invalid_state: 'This sign-in link has already been used or is no longer valid. Start a new sign-in below.',
  expired_state: 'Your sign-in attempt expired. Start again and complete the company sign-in steps.',
  provider_denied: 'Company sign-in was cancelled or declined. You can start again below.',
  missing_code: 'Company sign-in did not finish. Start a new sign-in below.',
  token_validation: 'We could not validate the company sign-in response. Start again. If this repeats, use the reference below to check the server logs.',
  identity_provider: 'The company identity service is currently unavailable. Try again shortly.',
  mfa_required: 'Account verification did not finish at the required MFA level. Verify again with your company account and authenticator.',
  session_expired: 'Your workspace session expired during verification. Sign in again to continue.',
  no_role: 'Your company account has no SOC role assigned. Your identity administrator needs to assign the appropriate role.',
  account_conflict: 'This company account conflicts with an existing SOC account. An administrator needs to check the account mapping.',
  account_disabled: 'This SOC account is disabled. Contact your administrator to restore access.',
};

export function LoginRecovery({ code, reference }: { code: string; reference?: string | null }) {
  const safeReference = reference && /^[a-zA-Z0-9_-]{1,64}$/.test(reference) ? reference : null;
  return <div className="login-recovery" role="alert">
    <strong>Sign-in needs another attempt</strong>
    <p>{MESSAGES[code] ?? 'Sign-in did not complete. Start again using your company account.'}</p>
    {safeReference && <small>Reference: <code>{safeReference}</code></small>}
  </div>;
}
