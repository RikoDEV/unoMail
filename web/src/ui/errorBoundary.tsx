import { Alert, Button } from '@mui/material';
import { Component, type ReactNode } from 'react';
import { useLocation } from 'react-router-dom';
import { t } from '../i18n';

interface State {
  failed: boolean;
}

/** Keeps one page's rendering error (from hostile message content, say) from blanking the app. */
class Boundary extends Component<{ children: ReactNode; resetKey: string }, State> {
  state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  componentDidCatch(error: unknown) {
    console.error('page failed to render', error);
  }

  componentDidUpdate(previous: { resetKey: string }) {
    // Going somewhere else is the way out: try again there.
    if (this.state.failed && previous.resetKey !== this.props.resetKey) this.setState({ failed: false });
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <Alert severity="error" sx={{ m: 2 }} action={<Button color="inherit" onClick={() => this.setState({ failed: false })}>{t('Try again')}</Button>}>
        {t('This page could not be shown.')}
      </Alert>
    );
  }
}

export function PageBoundary({ children }: { children: ReactNode }) {
  const location = useLocation();
  return <Boundary resetKey={location.pathname + location.search}>{children}</Boundary>;
}
