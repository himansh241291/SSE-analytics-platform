import './globals.css'

export const metadata = {
  title: 'SSE Security Analytics',
  description: 'Cisco SSE telemetry analytics and investigation platform',
}

export default function RootLayout({ children }) {
  return <html lang="en"><body>{children}</body></html>
}
