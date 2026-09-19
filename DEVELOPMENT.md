# Kavach — Local Development

## Start all three processes

### 1. Python API (scanner + shield)
```bash
# From repo root
pip install -r requirements.txt
API_KEY=dev-key uvicorn api.main:app --reload --port 8000
```

### 2. Node.js backend proxy
```bash
cd backend
cp .env.example .env   # set API_KEY=dev-key, PYTHON_API_URL=http://localhost:8000
npm install
npm start
```

### 3. React frontend
```bash
cd frontend
cp .env.example .env   # set VITE_API_KEY=dev-key
npm install
npm run dev
# Opens at http://localhost:5173
```

## Environment variables

| Variable | Where | Value |
|---|---|---|
| `API_KEY` | Python API + backend | Same secret key |
| `PYTHON_API_URL` | backend/.env | `http://localhost:8000` |
| `VITE_API_KEY` | frontend/.env | Same secret key |
| `SHIELD_AGENTS_TABLE` | Python API | DynamoDB table name (optional — falls back to in-memory) |
| `SHIELD_INCIDENTS_TABLE` | Python API | DynamoDB table name (optional — falls back to in-memory) |
| `SCANNER_BUCKET` | Python API | S3 bucket name (required for real scans) |
| `ARTIFACTS_TABLE` | Python API | DynamoDB table name (required for real scans) |
| `PIPELINE_STATE_MACHINE_ARN` | Python API | Step Functions ARN (required for real scans) |

## Deploy to AWS

See `README.md` for full SAM deployment instructions.

Scanner stack:
```bash
cd infrastructure/scanner
sam build && sam deploy
```

Shield stack:
```bash
cd infrastructure/shield
sam build && sam deploy --parameter-overrides LambdaImageUri=<ECR_URI>
```
