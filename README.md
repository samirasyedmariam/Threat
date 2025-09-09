from docx import Document

# Create a new document

doc = Document()

# Title

doc.add_heading('Threat Dashboard — CVE Ingest & Visualization', 0)

# Sections from the README

sections = [
("✨ Features", """

- 🔄 Scheduled **sync from NVD API** (chunked, de-duplicated, incremental or full refresh)
- 📂 Store CVE data in **PostgreSQL**
- 🔎 Filter CVEs by:
  - CVE ID
  - Year
  - CVSS Score (v2/v3)
  - Last modified in **N** days
- 📑 REST API with **pagination & sorting**
- 📊 Frontend (Next.js) with:
  - Server-side paging
  - Global + column filters
  - **Year dropdown** populated dynamically
  - CVE details page with CVSS metrics & raw JSON view
- 📜 API documentation (Swagger UI)
- ✅ Unit tests (JUnit5 + Mockito)
  """),
  ("📂 Project Structure", """
  /threat (Backend - Spring Boot)
  ├─ src/
  ├─ pom.xml
  └─ application.yml

/threat-frontend (Frontend - Next.js)
├─ src/
├─ package.json
└─ .env.local
"""),
("⚙️ Prerequisites", """

- Java 17
- Maven 3.6+
- Node.js 16+ (npm/yarn/pnpm)
- PostgreSQL 15+
- (Optional) Docker & Docker Compose
  """),
  ("🚀 Backend (Spring Boot)", """

1. Configure `src/main/resources/application.yml`:

spring:
datasource:
url: jdbc:postgresql://localhost:5432/threatdb
username: postgres
password: 1234
jpa:
hibernate:
ddl-auto: update

nvd:
base-url: https://services.nvd.nist.gov/rest/json/cves/2.0
api-key: "" # optional
page-size: 2000
sync-cron: "0 0 1 \* \* \*" # nightly
sync-on-startup: false

dev:
sync-token: "" # token required for POST /api/dev/sync

2. Build the project:
   mvn clean package

3. Run the backend:
   mvn spring-boot:run
   OR
   java -jar target/threat-0.0.1-SNAPSHOT.jar
   """),
   ("🌐 API Endpoints", """
   Base URL: http://localhost:8080/api

List CVEs:
GET /api/cves?page=0&size=10&year=2023&minScore=7&sort=lastModifiedDate&direction=desc

Get single CVE:
GET /api/cves/CVE-2023-12345

Manual sync:
POST /api/dev/sync

If dev.sync-token is set:
-H "X-ADMIN-TOKEN: your-token"
"""),
("📘 API Docs", """

- Swagger UI → http://localhost:8080/swagger-ui.html
- OpenAPI JSON → http://localhost:8080/v3/api-docs
  """),
  ("🧪 Run Tests", """
  mvn test
  """),
  ("🎨 Frontend (Next.js)", """

1. Configure `.env.local`:

NEXT_PUBLIC_API_BASE=http://localhost:8080/api

2. Install dependencies:
   cd threat-frontend
   npm install

3. Run the development server:
   npm run dev

Visit the frontend at: http://localhost:3000/cves
"""),
("🖥️ UI Routes", """

- /cves/list → CVE listing with:

  - Pagination
  - Global search
  - Column filters
  - Year dropdown

- /cves/[id] → CVE details (CVSS metrics, CPE matches, raw JSON)
  """),
  ("🐳 Docker Compose (optional)", """
  docker-compose.yml (in project root):

version: "3.8"
services:
db:
image: postgres:15
environment:
POSTGRES_DB: threatdb
POSTGRES_USER: postgres
POSTGRES_PASSWORD: 1234
ports: - "5432:5432"
volumes: - db-data:/var/lib/postgresql/data

app:
build: ./threat
environment:
SPRING_DATASOURCE_URL: jdbc:postgresql://db:5432/threatdb
SPRING_DATASOURCE_USERNAME: postgres
SPRING_DATASOURCE_PASSWORD: 1234
ports: - "8080:8080"
depends_on: - db

volumes:
db-data:
"""),
("▶️ Run Docker", """
docker compose up --build
"""),
("🔐 Security Notes", """

- Always protect /api/dev/sync with a strong dev.sync-token.
- Use HTTPS in production.
- Rotate NVD API keys if used.
- Disable spring.jpa.open-in-view in production to avoid lazy loading issues.
  """),
  ("🛠️ Troubleshooting", """
- Empty CVE list → Run POST /api/dev/sync to load data.
- CORS errors → Ensure backend allows http://localhost:3000.
- Build failures → Move tests into src/test/java/ (already fixed).
- DB connection issues → Check spring.datasource.url and ensure PostgreSQL is running.
  """),
  ("✅ Assessment Checklist", """
- [x] Consume NVD API & store in DB
- [x] Data cleansing & deduplication
- [x] Periodic batch sync (cron or manual)
- [x] API filtering (CVE ID, year, score, lastModifiedDays)
- [x] UI table + total records + results per page
- [x] Pagination & optional sorting
- [x] Details page /cves/[id] with API call
- [x] API documentation (Swagger)
- [x] Unit tests
      """),
      ("📌 Next Steps", """
- Add advanced filtering (multi-column, date ranges)
- Improve frontend table UX (sorting, server-side search)
- Deploy with Docker + Kubernetes
- Add authentication & role-based access
  """)
  ]

# Add each section to the document

for title, content in sections:
doc.add_heading(title, level=1)
for line in content.strip().splitlines():
doc.add_paragraph(line)

# Save the document

output_path = "/mnt/data/Threat_Dashboard_Documentation.docx"
doc.save(output_path)

output_path
