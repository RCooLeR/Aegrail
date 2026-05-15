import { KeyRound, Loader2 } from "lucide-react";
import { FormEvent, useState } from "react";
import { createHubUser, loginHubUser, MFARequiredError } from "../../api";
import type { ApiScope, HubAuthMe } from "../../types";
import { InlineAlert, TextInput } from "./common";

export function AuthGate({
  auth,
  error,
  loading,
  onAuthenticated,
  scope
}: {
  auth: HubAuthMe | null;
  error: string;
  loading: boolean;
  onAuthenticated: () => Promise<void>;
  scope: ApiScope;
}) {
  const requiresBootstrap = Boolean(auth?.requires_bootstrap);
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [mfaRequired, setMFARequired] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setFormError("");
    try {
      if (requiresBootstrap) {
        await createHubUser(scope, {
          access_level: "owner",
          display_name: displayName,
          email,
          password,
          status: "active",
          two_factor_required: true
        });
      }
      await loginHubUser(scope, { email, password, totp_code: totpCode });
      setMFARequired(false);
      await onAuthenticated();
    } catch (caught) {
      if (caught instanceof MFARequiredError) {
        setMFARequired(true);
        setFormError("Enter your 2FA code to finish signing in.");
      } else {
        setFormError(caught instanceof Error ? caught.message : String(caught));
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="auth-shell">
      <section className="auth-card">
        <img src={`${import.meta.env.BASE_URL}aegrail-horizontal-white.png`} alt="Aegrail" />
        <div>
          <p className="eyebrow">{requiresBootstrap ? "First user setup" : "Protected dashboard"}</p>
          <h1>{requiresBootstrap ? "Create owner access" : "Sign in"}</h1>
        </div>
        <form className="form-stack" onSubmit={submit}>
          {requiresBootstrap && <TextInput label="Name" value={displayName} onChange={setDisplayName} />}
          <TextInput label="Email" value={email} onChange={(value) => {
            setEmail(value);
            setMFARequired(false);
          }} />
          <label>
            Password
            <input
              autoComplete={requiresBootstrap ? "new-password" : "current-password"}
              minLength={12}
              required
              type="password"
              value={password}
              onChange={(event) => {
                setPassword(event.target.value);
                setMFARequired(false);
              }}
            />
          </label>
          {(mfaRequired || !requiresBootstrap) && (
            <label>
              2FA code
              <input
                autoComplete="one-time-code"
                inputMode="numeric"
                maxLength={8}
                placeholder={mfaRequired ? "123456" : "Optional until enabled"}
                value={totpCode}
                onChange={(event) => setTotpCode(event.target.value)}
              />
            </label>
          )}
          {(error || formError) && <InlineAlert message={formError || error} />}
          <button className="primary-button" disabled={loading || submitting} type="submit">
            {loading || submitting ? <Loader2 size={16} className="spin" /> : <KeyRound size={16} />}
            {requiresBootstrap ? "Create and sign in" : "Sign in"}
          </button>
        </form>
      </section>
    </main>
  );
}
