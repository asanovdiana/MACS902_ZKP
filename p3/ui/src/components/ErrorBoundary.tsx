import { Component, type ReactNode } from 'react';
import { AlertTriangle } from 'lucide-react';

/** Keeps one failing screen from blanking the whole console during a live demo. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  override render() {
    if (!this.state.error) return this.props.children;
    return (
      <div role="alert" className="panel flex items-start gap-3 p-6">
        <AlertTriangle className="h-6 w-6 shrink-0 text-warn" />
        <div>
          <div className="font-medium">This screen hit an unexpected error.</div>
          <p className="mono mt-1 text-xs text-ink-400">{this.state.error.message}</p>
          <button
            className="mt-3 text-sm text-accent hover:underline"
            onClick={() => this.setState({ error: null })}
          >
            Try again
          </button>
        </div>
      </div>
    );
  }
}
