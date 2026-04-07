// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import rehypeMermaid from 'rehype-mermaid';

export default defineConfig({
	site: 'https://dwaar.dev',
	vite: {
		build: { sourcemap: false },
	},
	markdown: {
		rehypePlugins: [[rehypeMermaid, { strategy: 'img-svg' }]],
	},
	integrations: [
		starlight({
			title: 'Dwaar',
			description: 'High-performance reverse proxy. Pingora performance. Caddy simplicity.',
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/permanu/Dwaar' },
			],
			editLink: { baseUrl: 'https://github.com/permanu/Dwaar/edit/main/site/' },
			head: [
				{ tag: 'meta', attrs: { name: 'og:image', content: '/og.png' } },
				{ tag: 'meta', attrs: { name: 'color-scheme', content: 'dark' } },
				{
					tag: 'script',
					content: `document.documentElement.dataset.theme = 'dark'; localStorage.setItem('starlight-theme', 'dark');`,
				},
			],
			customCss: ['./src/styles/custom.css'],
			// Force dark mode — match landing page
			defaultLocale: 'en',
			expressiveCode: {
				themes: ['github-dark'],
				styleOverrides: {
					borderRadius: '8px',
					borderColor: 'rgba(255, 255, 255, 0.06)',
					codeBackground: '#111114',
					frames: {
						editorTabBarBackground: '#141417',
						terminalBackground: '#111114',
						terminalTitlebarBackground: '#141417',
					},
				},
			},
			sidebar: [
				{
					label: 'Getting Started',
					items: [
						{ label: 'What is Dwaar?', slug: 'getting-started/what-is-dwaar' },
						{ label: 'Installation', slug: 'getting-started/installation' },
						{ label: 'Quick Start', slug: 'getting-started/quickstart' },
						{ label: 'Comparison', slug: 'getting-started/comparison' },
					],
				},
				{
					label: 'Configuration',
					items: [
						{ label: 'Dwaarfile Reference', slug: 'configuration/dwaarfile' },
						{ label: 'Global Options', slug: 'configuration/global-options' },
						{ label: 'Named Matchers', slug: 'configuration/named-matchers' },
						{ label: 'Placeholders & Variables', slug: 'configuration/placeholders' },
						{ label: 'CLI Reference', slug: 'configuration/cli' },
						{ label: 'Environment Variables', slug: 'configuration/environment' },
					],
				},
				{
					label: 'Routing & Handlers',
					items: [
						{ label: 'Reverse Proxy', slug: 'routing/reverse-proxy' },
						{ label: 'File Server', slug: 'routing/file-server' },
						{ label: 'FastCGI / PHP', slug: 'routing/fastcgi' },
						{ label: 'Redirects & Rewrites', slug: 'routing/redirects-rewrites' },
						{ label: 'Handle & Route Blocks', slug: 'routing/handle' },
						{ label: 'Respond & Error Pages', slug: 'routing/respond-errors' },
					],
				},
				{
					label: 'HTTPS & TLS',
					items: [
						{ label: 'Automatic HTTPS', slug: 'tls/automatic-https' },
						{ label: 'DNS-01 (Wildcards)', slug: 'tls/dns-challenge' },
						{ label: 'Manual Certificates', slug: 'tls/manual-certs' },
						{ label: 'Self-Signed (Dev)', slug: 'tls/self-signed' },
						{ label: 'Mutual TLS (mTLS)', slug: 'tls/mtls' },
						{ label: 'OCSP Stapling', slug: 'tls/ocsp-stapling' },
					],
				},
				{
					label: 'Security',
					items: [
						{ label: 'Rate Limiting', slug: 'security/rate-limiting' },
						{ label: 'IP Filtering', slug: 'security/ip-filtering' },
						{ label: 'Bot Detection', slug: 'security/bot-detection' },
						{ label: 'Security Headers', slug: 'security/security-headers' },
						{ label: 'Basic Auth', slug: 'security/basic-auth' },
						{ label: 'Forward Auth', slug: 'security/forward-auth' },
					],
				},
				{
					label: 'Performance',
					items: [
						{ label: 'Compression', slug: 'performance/compression' },
						{ label: 'HTTP Caching', slug: 'performance/caching' },
						{ label: 'HTTP/3 (QUIC)', slug: 'performance/http3' },
						{ label: 'Timeouts & Draining', slug: 'performance/timeouts' },
						{ label: 'Load Balancing', slug: 'performance/load-balancing' },
					],
				},
				{
					label: 'Observability',
					items: [
						{ label: 'Request Logging', slug: 'observability/logging' },
						{ label: 'First-Party Analytics', slug: 'observability/analytics' },
						{ label: 'Prometheus Metrics', slug: 'observability/prometheus' },
						{ label: 'Distributed Tracing', slug: 'observability/tracing' },
						{ label: 'GeoIP', slug: 'observability/geoip' },
					],
				},
				{
					label: 'Plugins',
					items: [
						{ label: 'Plugin System', slug: 'plugins/overview' },
						{ label: 'WASM Plugins', slug: 'plugins/wasm-plugins' },
						{ label: 'Native Plugins', slug: 'plugins/native-plugins' },
					],
				},
				{
					label: 'Admin API',
					items: [
						{ label: 'API Reference', slug: 'api/admin' },
						{ label: 'Analytics API', slug: 'api/analytics' },
						{ label: 'Cache Purge', slug: 'api/cache-purge' },
					],
				},
				{
					label: 'Deployment',
					items: [
						{ label: 'Docker', slug: 'deployment/docker' },
						{ label: 'Docker Labels', slug: 'deployment/docker-labels' },
						{ label: 'Kubernetes', slug: 'deployment/kubernetes' },
						{ label: 'Helm Chart', slug: 'deployment/helm' },
						{ label: 'Systemd', slug: 'deployment/systemd' },
						{ label: 'Zero-Downtime', slug: 'deployment/zero-downtime' },
					],
				},
				{
					label: 'Migration Guides',
					items: [
						{ label: 'From Caddy', slug: 'migration/from-caddy' },
						{ label: 'From Nginx', slug: 'migration/from-nginx' },
						{ label: 'From Traefik', slug: 'migration/from-traefik' },
					],
				},
				{
					label: 'Architecture',
					items: [
						{ label: 'Overview', slug: 'architecture/overview' },
						{ label: 'Request Lifecycle', slug: 'architecture/request-lifecycle' },
						{ label: 'Performance Internals', slug: 'architecture/performance' },
						{ label: 'Crate Map', slug: 'architecture/crate-map' },
					],
				},
				{
					label: 'Contributing',
					items: [
						{ label: 'Development Setup', slug: 'contributing/development' },
						{ label: 'Architecture', slug: 'contributing/architecture' },
					],
				},
				{
					label: 'Appendix',
					items: [
						{ label: 'Troubleshooting', slug: 'appendix/troubleshooting' },
						{ label: 'Changelog', slug: 'appendix/changelog' },
					],
				},
			],
		}),
	],
});
