/**
 * Copyright 2020 Inrupt Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

import { foaf, schema } from "rdf-namespaces";
import {
  getSolidDataset,
  setThing,
  getThing,
  getStringNoLocale,
  setDatetime,
  setStringNoLocale,
  saveSolidDatasetAt,
  isRawData,
  getContentType,
  fetchResourceInfoWithAcl,
  getSolidDatasetWithAcl,
  hasResourceAcl,
  getPublicAccess,
  getAgentAccess,
  getFallbackAcl,
  getResourceAcl,
  getAgentResourceAccess,
  setAgentResourceAccess,
  saveAclFor,
  hasFallbackAcl,
  hasAccessibleAcl,
  createAclFromFallbackAcl,
  getPublicDefaultAccess,
  getPublicResourceAccess,
  getFile,
} from "./index";

describe("End-to-end tests", () => {
  it("should be able to read and update data in a Pod", async () => {
    const randomNick = "Random nick " + Math.random();

    const dataset = await getSolidDataset(
      "https://lit-e2e-test.inrupt.net/public/lit-pod-test.ttl"
    );
    const existingThing = getThing(
      dataset,
      "https://lit-e2e-test.inrupt.net/public/lit-pod-test.ttl#thing1"
    );

    expect(getStringNoLocale(existingThing, foaf.name)).toBe(
      "Thing for first end-to-end test"
    );

    let updatedThing = setDatetime(
      existingThing,
      schema.dateModified,
      new Date()
    );
    updatedThing = setStringNoLocale(updatedThing, foaf.nick, randomNick);

    const updatedDataset = setThing(dataset, updatedThing);
    const savedDataset = await saveSolidDatasetAt(
      "https://lit-e2e-test.inrupt.net/public/lit-pod-test.ttl",
      updatedDataset
    );

    const savedThing = getThing(
      savedDataset,
      "https://lit-e2e-test.inrupt.net/public/lit-pod-test.ttl#thing1"
    );
    expect(getStringNoLocale(savedThing, foaf.name)).toBe(
      "Thing for first end-to-end test"
    );
    expect(getStringNoLocale(savedThing, foaf.nick)).toBe(randomNick);
  });

  it("can differentiate between RDF and non-RDF Resources", async () => {
    const rdfResourceInfo = await fetchResourceInfoWithAcl(
      "https://lit-e2e-test.inrupt.net/public/lit-pod-resource-info-test/litdataset.ttl"
    );
    const nonRdfResourceInfo = await fetchResourceInfoWithAcl(
      "https://lit-e2e-test.inrupt.net/public/lit-pod-resource-info-test/not-a-litdataset.png"
    );
    expect(isRawData(rdfResourceInfo)).toBe(false);
    expect(isRawData(nonRdfResourceInfo)).toBe(true);
  });

  it("should be able to read and update ACLs", async () => {
    const fakeWebId =
      "https://example.com/fake-webid#" +
      Date.now().toString() +
      Math.random().toString();

    const datasetWithAcl = await getSolidDatasetWithAcl(
      "https://lit-e2e-test.inrupt.net/public/lit-pod-acl-test/passthrough-container/resource-with-acl.ttl"
    );
    const datasetWithoutAcl = await getSolidDatasetWithAcl(
      "https://lit-e2e-test.inrupt.net/public/lit-pod-acl-test/passthrough-container/resource-without-acl.ttl"
    );

    expect(hasResourceAcl(datasetWithAcl)).toBe(true);
    expect(hasResourceAcl(datasetWithoutAcl)).toBe(false);
    expect(getPublicAccess(datasetWithAcl)).toEqual({
      read: true,
      append: true,
      write: true,
      control: true,
    });
    expect(
      getAgentAccess(
        datasetWithAcl,
        "https://vincentt.inrupt.net/profile/card#me"
      )
    ).toEqual({
      read: false,
      append: true,
      write: false,
      control: false,
    });
    expect(
      getAgentAccess(
        datasetWithoutAcl,
        "https://vincentt.inrupt.net/profile/card#me"
      )
    ).toEqual({
      read: true,
      append: false,
      write: false,
      control: false,
    });
    const fallbackAclForDatasetWithoutAcl = getFallbackAcl(datasetWithoutAcl);
    expect(fallbackAclForDatasetWithoutAcl?.internal_accessTo).toBe(
      "https://lit-e2e-test.inrupt.net/public/lit-pod-acl-test/"
    );

    if (hasResourceAcl(datasetWithAcl)) {
      const acl = getResourceAcl(datasetWithAcl);
      const updatedAcl = setAgentResourceAccess(acl, fakeWebId, {
        read: true,
        append: false,
        write: false,
        control: false,
      });
      const savedAcl = await saveAclFor(datasetWithAcl, updatedAcl);
      const fakeWebIdAccess = getAgentResourceAccess(savedAcl, fakeWebId);
      expect(fakeWebIdAccess).toEqual({
        read: true,
        append: false,
        write: false,
        control: false,
      });

      // Cleanup
      const cleanedAcl = setAgentResourceAccess(savedAcl, fakeWebId, {
        read: false,
        append: false,
        write: false,
        control: false,
      });
      await saveAclFor(datasetWithAcl, cleanedAcl);
    }
  });

  it("can copy default rules from the fallback ACL as Resource rules to a new ACL", async () => {
    const dataset = await getSolidDatasetWithAcl(
      "https://lit-e2e-test.inrupt.net/public/lit-pod-acl-initialisation-test/resource.ttl"
    );
    if (
      hasFallbackAcl(dataset) &&
      hasAccessibleAcl(dataset) &&
      !hasResourceAcl(dataset)
    ) {
      const newResourceAcl = createAclFromFallbackAcl(dataset);
      const existingFallbackAcl = getFallbackAcl(dataset);
      expect(getPublicDefaultAccess(existingFallbackAcl)).toEqual(
        getPublicResourceAccess(newResourceAcl)
      );
    }
  });

  it("can fetch a non-RDF file and its metadata", async () => {
    const jsonFile = await getFile(
      "https://lit-e2e-test.inrupt.net/public/arbitrary.json"
    );

    expect(getContentType(jsonFile)).toEqual("application/json");

    const data = JSON.parse(await jsonFile.text());
    expect(data).toEqual({ arbitrary: "json data" });
  });
});
