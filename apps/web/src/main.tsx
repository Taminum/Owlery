import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import './index.css'
import { AuthProvider } from './lib/auth'
import { Layout } from './components/Layout'
import Destinations from './pages/Destinations'
import Alerts from './pages/Alerts'
import Channels from './pages/Channels'
import Live from './pages/Live'
import Devices from './pages/Devices'
import Digest from './pages/Digest'
import Awg from './pages/Awg'
import Billing from './pages/Billing'
import Intel from './pages/Intel'
import { DnsMapDetail } from './pages/DnsMap'
import Security, { SecurityDetail } from './pages/Security'
import Sites from './pages/Sites'
import Traffic from './pages/Traffic'
import Nodes from './pages/Nodes'
import Users from './pages/Users'
import Overview from './pages/Overview'
import Panels from './pages/Panels'
import Placeholder from './pages/Placeholder'
import Settings from './pages/Settings'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Overview />} />
            <Route path="traffic" element={<Traffic />} />
            <Route path="live" element={<Live />} />
            <Route path="channels" element={<Channels />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="sites" element={<Sites />} />
            <Route path="intel" element={<Intel />} />
            <Route path="intel/dns/:id" element={<DnsMapDetail />} />
            <Route path="security" element={<Security />} />
            <Route path="security/:id" element={<SecurityDetail />} />
            <Route path="awg" element={<Awg />} />
            <Route path="billing" element={<Billing />} />
            <Route path="domains" element={<Destinations />} />
            <Route path="users" element={<Users />} />
            <Route path="nodes" element={<Nodes />} />
            <Route path="devices" element={<Devices />} />
            <Route path="digest" element={<Digest />} />
            <Route path="panels" element={<Panels />} />
            <Route path="settings" element={<Settings />} />
            <Route path="*" element={<Placeholder />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
)
