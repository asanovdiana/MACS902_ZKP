import { Navigate, Route, Routes } from 'react-router-dom';
import { OperatorProvider, useOperator } from '../state/operator';
import { EventStreamProvider } from '../hooks/useEventStream';
import { Layout } from './Layout';
import { LoginPage } from '../pages/Login';
import { PortalPage } from '../pages/Portal';
import { LiveViewPage } from '../pages/LiveView';
import { ComparePage } from '../pages/Compare';
import { AdminPage } from '../pages/Admin';
import { AttackLabPage } from '../pages/AttackLab';
import { PerformancePage } from '../pages/Performance';
import { IntegrationPage } from '../pages/Integration';
import { Loader2 } from 'lucide-react';

function Gate() {
  const { authenticated } = useOperator();
  if (authenticated === null)
    return (
      <div className="grid h-full place-items-center text-ink-400">
        <Loader2 className="h-6 w-6 animate-spin" aria-label="Loading" />
      </div>
    );
  if (!authenticated) return <LoginPage />;
  return (
    <EventStreamProvider>
      <Layout>
        <Routes>
          <Route path="/" element={<Navigate to="/portal" replace />} />
          <Route path="/portal" element={<PortalPage />} />
          <Route path="/live" element={<LiveViewPage />} />
          <Route path="/compare" element={<ComparePage />} />
          <Route path="/admin" element={<AdminPage />} />
          <Route path="/attacks" element={<AttackLabPage />} />
          <Route path="/performance" element={<PerformancePage />} />
          <Route path="/integration" element={<IntegrationPage />} />
          <Route path="*" element={<Navigate to="/portal" replace />} />
        </Routes>
      </Layout>
    </EventStreamProvider>
  );
}

export function App() {
  return (
    <OperatorProvider>
      <Gate />
    </OperatorProvider>
  );
}
