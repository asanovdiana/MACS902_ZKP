import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { api } from '../services/api';

interface OperatorState {
  authenticated: boolean | null;
  login: (token: string) => Promise<void>;
  logout: () => Promise<void>;
}
const Ctx = createContext<OperatorState | null>(null);

export function OperatorProvider({ children }: { children: ReactNode }) {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  useEffect(() => {
    api
      .operatorMe()
      .then((r) => setAuthenticated(r.authenticated))
      .catch(() => setAuthenticated(false));
  }, []);
  const login = useCallback(async (token: string) => {
    await api.operatorLogin(token);
    setAuthenticated(true);
  }, []);
  const logout = useCallback(async () => {
    await api.operatorLogout().catch(() => undefined);
    setAuthenticated(false);
  }, []);
  return <Ctx.Provider value={{ authenticated, login, logout }}>{children}</Ctx.Provider>;
}

export function useOperator() {
  const v = useContext(Ctx);
  if (!v) throw new Error('useOperator outside provider');
  return v;
}
