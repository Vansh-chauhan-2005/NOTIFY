import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface ErrorBoundaryState {
  hasError: boolean;
  errorMessage: string | null;
}

export class ErrorBoundary extends React.Component<
  { children: React.ReactNode; fallbackTitle?: string },
  ErrorBoundaryState
> {
  constructor(props: { children: React.ReactNode; fallbackTitle?: string }) {
    super(props);
    this.state = { hasError: false, errorMessage: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      errorMessage: error?.message || 'An unexpected error occurred.',
    };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[React ErrorBoundary]', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="glass-panel rounded-2xl border border-[#D9468F]/40 bg-[#FCECF4]/70 p-6 text-center space-y-3">
          <div className="flex justify-center">
            <div className="w-10 h-10 rounded-full bg-[#D9468F]/15 text-[#B52A70] flex items-center justify-center">
              <AlertTriangle className="w-5 h-5" />
            </div>
          </div>
          <h3 className="text-sm font-semibold text-[#16161D]">
            {this.props.fallbackTitle || 'Something went wrong in this panel'}
          </h3>
          <p className="text-xs text-[#464451] max-w-md mx-auto break-words">
            {this.state.errorMessage}
          </p>
          <button
            type="button"
            onClick={() => this.setState({ hasError: false, errorMessage: null })}
            className="inline-flex items-center space-x-2 px-4 py-2 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-xs font-semibold text-[#FAF6F0] transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Retry Panel</span>
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
