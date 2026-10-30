import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import { AppRoutes } from './app/routes'
import { AuthProvider } from './auth/AuthProvider'
import { ToastProvider } from './components/toast/ToastProvider'
import { VersionBanner } from './components/VersionBanner'
import { ThemeProvider } from './themes/ThemeProvider'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 15_000,
      refetchOnWindowFocus: false,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <VersionBanner />
        {/* Inside AuthProvider, because the theme is a property of the SESSION
            and the reconcile has to re-ask when the identity changes — sign-in
            is SPA-local, so a provider above it would only ever ask once, at a
            moment when nobody was signed in. The first paint is not this
            provider's job: `main.tsx` applies the cached theme synchronously
            before React mounts. */}
        <AuthProvider>
          <ThemeProvider>
            <BrowserRouter>
              <AppRoutes />
            </BrowserRouter>
          </ThemeProvider>
        </AuthProvider>
      </ToastProvider>
    </QueryClientProvider>
  )
}
