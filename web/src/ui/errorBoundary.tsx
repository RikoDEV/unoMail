import { Component, type ReactNode } from 'react';
import { useLocation } from 'react-router-dom';
import { isUnreachable, ProblemPage } from './ProblemPage';

interface State {
  failed: 'unreachable' | 'failed' | null;
}

const reload = () => window.location.reload();

/** Keeps one page's rendering error (from hostile message content, say) from blanking the app. */
class Boundary extends Component<{ children: ReactNode; resetKey: string }, State> {
  state: State = { failed: null };

  // A page whose code could not be downloaded means the server is gone, not that the page is broken.
  static getDerivedStateFromError(error: unknown): State {
    return { failed: isUnreachable(error) ? 'unreachable' : 'failed' };
  }

  componentDidCatch(error: unknown) {
    console.error('page failed to render', error);
  }

  componentDidUpdate(previous: { resetKey: string }) {
    // Going somewhere else is the way out: try again there.
    if (this.state.failed && previous.resetKey !== this.props.resetKey) this.setState({ failed: null });
  }

  retry = () => this.setState({ failed: null });

  render() {
    if (!this.state.failed) return this.props.children;
    // Code that failed to load stays failed until the page is loaded again.
    return <ProblemPage kind={this.state.failed} onRetry={this.state.failed === 'unreachable' ? reload : this.retry} />;
  }
}

export function PageBoundary({ children }: { children: ReactNode }) {
  const location = useLocation();
  return <Boundary resetKey={location.pathname + location.search}>{children}</Boundary>;
}
