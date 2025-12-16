# Setup Guide

## 1. Clone the Repository  
(Must have a Cloudflare account)

```bash
git clone <repo-url>
cd <repo-folder>

npm install
npm install -D wrangler
npx wrangler login
````

---

## 2. Create a D1 Database

```bash
npx wrangler d1 create file_share
```

Output will look like:

```
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

➡️ Copy `database_id` into your `wrangler.toml`.

---

## 4. Initialize the Database Schema

```bash
npx wrangler d1 execute file_share --file=./schema.sql
```

---

## 5. Development Mode

```bash
npm run dev
```

---

## 6. Deploy to Cloudflare

```bash
npm run deploy
```
