---
id: getting-started
title: Getting Started with solid-client
sidebar_label: Getting Started
---

:::caution

The documentation is still being written; here be dragons!

:::

## Installation

solid-client is available as a package on npm, and can be used in the browser with a module bundler like Webpack, or in Node.js.

```bash
npm install @inrupt/solid-client
```

If [solid-auth-client](https://www.npmjs.com/package/solid-auth-client) is installed,
solid-client will automatically use it to make authenticated requests.
If no such authenticated fetcher is provided, only public [Resources](./glossary.mdx#resource) can be accessed.

## Quick start

:::info

If you are looking for a more thorough introduction, you can work your way through the full [Guide](./guide/installation.md).

:::

### Fetching data

```typescript
import { fetchLitDataset } from "@inrupt/solid-client";

const profileResource = await fetchLitDataset(
  "https://vincentt.inrupt.net/profile/card"
);
```

### Reading data

```typescript
import { getThingOne, getStringNoLocaleOne } from "@inrupt/solid-client";
import { foaf } from "rdf-namespaces";

const profile = getThingOne(
  profileResource,
  "https://vincentt.inrupt.net/profile/card#me"
);
const name = getStringNoLocaleOne(profileResource, foaf.name);
```

For more details, see [Working with Data](./tutorials/working-with-data.md#reading-data).

### Writing data

```typescript
import {
  setStringUnlocalised,
  setThing,
  saveLitDatasetAt,
} from "@inrupt/solid-client";
import { foaf } from "rdf-namespaces";

const updatedProfile = setStringUnlocalised(profile, foaf.name, "Vincent");
const updatedProfileResource = setThing(profileDoc, updatedProfile);

await saveLitDatasetAt(
  "https://vincentt.inrupt.net/profile/card",
  updatedProfileResource
);
```

For more details, see [Working with Data](./tutorials/working-with-data.md#writing-data).
