export default function HomePage() {
  return (
    <div className="text-center space-y-6">
      <h2 className="text-3xl font-bold">Welcome to the Threat Dashboard</h2>
      <p className="text-gray-600 max-w-2xl mx-auto">
        This dashboard lets you browse CVE (Common Vulnerabilities and Exposures) data
        stored in your backend. Use the navigation bar above to view the CVE list
        and click any CVE to explore detailed metrics, configurations, and references.
      </p>
      <a
        href="/cves"
        className="inline-block bg-blue-600 text-white px-6 py-2 rounded-lg shadow hover:bg-blue-700"
      >
        View CVEs
      </a>
    </div>
  )
}
