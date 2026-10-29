# D-Voting hosted demo: the whole election on one port.
#
#   docker build -t d-voting .
#   docker run -p 10000:10000 d-voting        # then open http://localhost:10000/demo
#
# Node runs the TypeScript sources directly (native type stripping), so there
# is no build step; the two browser bundles are committed with their SHA-256.

FROM node:24-slim

ENV NODE_ENV=production \
    PORT=10000
WORKDIR /app

# Install production dependencies first, for layer caching.
COPY package.json package-lock.json ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/ledger/package.json packages/ledger/
COPY packages/verifier/package.json packages/verifier/
COPY services/ballot-box/package.json services/ballot-box/
COPY services/registration/package.json services/registration/
COPY services/trustee/package.json services/trustee/
COPY services/validator/package.json services/validator/
COPY services/witness/package.json services/witness/
RUN npm ci --omit=dev --no-audit --no-fund

COPY packages ./packages
COPY services ./services
COPY deploy ./deploy

# Run as the unprivileged user the image provides.
USER node
EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s CMD node -e "fetch('http://localhost:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "deploy/hosted.ts"]
