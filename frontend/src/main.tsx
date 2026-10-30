import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource-variable/inter/index.css'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/500.css'
import './index.css'
import App from './App'
import { applyTheme, cachedTheme } from './themes/applyTheme'

// Before React mounts, and synchronously. `ThemeProvider` applies the same
// value in an effect, but an effect runs after the first paint: without this
// line a cold load shows the default palette for a frame and then swaps, which
// is exactly the flash an examiner who chose a light skin would notice most.
applyTheme(cachedTheme(), document.documentElement)

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
