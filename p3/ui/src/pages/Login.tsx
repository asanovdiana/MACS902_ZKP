import { useState, type FormEvent } from 'react';
import { KeyRound, ShieldCheck } from 'lucide-react';
import { useOperator } from '../state/operator';
import { Button, inputCls } from '../components/ui';

export function LoginPage() {
  const { login } = useOperator();
  const [token, setToken] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(token);
    } catch {
      setError('Invalid operator token.');
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="grid-bg grid h-full place-items-center px-4">
      <form onSubmit={submit} className="panel w-full max-w-md p-8">
        <div className="mb-6 flex items-center gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-xl bg-cyan-500/10 ring-1 ring-cyan-400/40">
            <ShieldCheck className="h-6 w-6 text-accent" />
          </div>
          <div>
            <h1 className="text-lg font-semibold">ZK Access Gate</h1>
            <p className="text-xs text-ink-400">Demonstration console · operator sign-in</p>
          </div>
        </div>
        <p className="mb-5 text-sm leading-relaxed text-ink-300">
          The console streams gateway security events and exposes registry administration, so it
          requires the operator token configured as{' '}
          <code className="mono text-accent">OPERATOR_TOKEN</code>.
        </p>
        <label htmlFor="token" className="mb-1 block text-xs font-medium text-ink-300">
          Operator token
        </label>
        <input
          id="token"
          type="password"
          autoComplete="current-password"
          className={inputCls}
          value={token}
          onChange={(e) => setToken(e.target.value)}
          required
          minLength={8}
        />
        {error && (
          <p role="alert" className="mt-2 text-sm text-bad">
            {error}
          </p>
        )}
        <Button type="submit" className="mt-5 w-full" loading={busy}>
          <KeyRound className="h-4 w-4" /> Sign in
        </Button>
      </form>
    </div>
  );
}
