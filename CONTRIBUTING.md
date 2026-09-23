# Contributing

## Development requirements

- Node.js 20 or newer.
- Keep secrets in `.env`; never commit `.env` or tokens.
- Use the existing ESM module style and two-space indentation.
- Keep webhook handlers fast and return `200` after successful delivery so Webflow does not retry them.
- Verify Webflow signatures before parsing or processing event data.
- Persist OAuth installations and webhook metadata in encrypted storage before production use.

## Checks before committing

```sh
npm run check
npm run format:check
npm test
```

Use `npm run format` to apply the project formatter.
