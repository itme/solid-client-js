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

import { describe, it, expect } from "@jest/globals";
jest.mock("../fetcher.ts", () => ({
  fetch: jest.fn().mockImplementation(() =>
    Promise.resolve(
      new Response(undefined, {
        headers: { Location: "https://arbitrary.pod/resource" },
      })
    )
  ),
}));

import { Response } from "cross-fetch";
import { dataset } from "@rdfjs/dataset";
import { DataFactory } from "n3";
import {
  internal_fetchResourceAcl,
  internal_fetchFallbackAcl,
  internal_getAccess,
  internal_getAclRules,
  internal_getResourceAclRules,
  internal_getDefaultAclRules,
  internal_getResourceAclRulesForResource,
  internal_getDefaultAclRulesForResource,
  internal_combineAccessModes,
  unstable_getResourceAcl,
  unstable_getFallbackAcl,
  internal_removeEmptyAclRules,
  unstable_createAclFromFallbackAcl,
  unstable_saveAclFor,
  unstable_deleteAclFor,
  unstable_createAcl,
} from "./acl";
import {
  WithResourceInfo,
  ThingPersisted,
  unstable_AclRule,
  unstable_AclDataset,
  unstable_Access,
  unstable_WithAccessibleAcl,
} from "../interfaces";

function mockResponse(
  body?: BodyInit | null,
  init?: ResponseInit & { url: string }
): Response {
  return new Response(body, init);
}

describe("fetchResourceAcl", () => {
  it("returns the fetched ACL LitDataset", async () => {
    const sourceDataset: WithResourceInfo = {
      internal_resourceInfo: {
        fetchedFrom: "https://some.pod/resource",
        isLitDataset: true,
        unstable_aclUrl: "https://some.pod/resource.acl",
      },
    };
    const mockFetch = jest
      .fn(window.fetch)
      .mockReturnValueOnce(
        Promise.resolve(
          mockResponse(undefined, { url: "https://some.pod/resource.acl" })
        )
      );

    const fetchedAcl = await internal_fetchResourceAcl(sourceDataset, {
      fetch: mockFetch,
    });

    expect(fetchedAcl?.internal_accessTo).toBe("https://some.pod/resource");
    expect(fetchedAcl?.internal_resourceInfo.fetchedFrom).toBe(
      "https://some.pod/resource.acl"
    );
    expect(mockFetch.mock.calls).toHaveLength(1);
    expect(mockFetch.mock.calls[0][0]).toBe("https://some.pod/resource.acl");
  });

  it("calls the included fetcher by default", async () => {
    const sourceDataset: WithResourceInfo = {
      internal_resourceInfo: {
        fetchedFrom: "https://some.pod/resource",
        isLitDataset: true,
        unstable_aclUrl: "https://some.pod/resource.acl",
      },
    };
    const mockedFetcher = jest.requireMock("../fetcher.ts") as {
      fetch: jest.Mock<
        ReturnType<typeof window.fetch>,
        [RequestInfo, RequestInit?]
      >;
    };

    await internal_fetchResourceAcl(sourceDataset);

    expect(mockedFetcher.fetch.mock.calls).toEqual([
      ["https://some.pod/resource.acl"],
    ]);
  });

  it("returns null if the source LitDataset has no known ACL IRI", async () => {
    const sourceDataset: WithResourceInfo = {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource",
        isLitDataset: true,
      },
    };

    const fetchedAcl = await internal_fetchResourceAcl(sourceDataset);

    expect(fetchedAcl).toBeNull();
  });

  it("returns null if the ACL was not found", async () => {
    const sourceDataset: WithResourceInfo = {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource",
        isLitDataset: true,
        unstable_aclUrl: "https://some.pod/resource.acl",
      },
    };
    const mockFetch = jest.fn(window.fetch).mockReturnValueOnce(
      Promise.resolve(
        mockResponse("ACL not found", {
          status: 404,
          url: "https://some.pod/resource.acl",
        })
      )
    );

    const fetchedAcl = await internal_fetchResourceAcl(sourceDataset, {
      fetch: mockFetch,
    });

    expect(fetchedAcl).toBeNull();
    expect(mockFetch.mock.calls).toHaveLength(1);
    expect(mockFetch.mock.calls[0][0]).toBe("https://some.pod/resource.acl");
  });
});

describe("fetchFallbackAcl", () => {
  it("returns the parent Container's ACL LitDataset, if present", async () => {
    const sourceDataset = {
      internal_resourceInfo: {
        fetchedFrom: "https://some.pod/resource",
        isLitDataset: true,
        // If no ACL IRI is given, the user does not have Control Access,
        // in which case we wouldn't be able to reliably determine the effective ACL.
        // Hence, the function requires the given LitDataset to have one known:
        unstable_aclUrl: "https://arbitrary.pod/resource.acl",
      },
    };
    const mockFetch = jest.fn(window.fetch).mockReturnValueOnce(
      Promise.resolve(
        mockResponse("", {
          headers: {
            Link: '<.acl>; rel="acl"',
          },
          url: "https://some.pod/",
        })
      )
    );
    mockFetch.mockReturnValueOnce(
      Promise.resolve(mockResponse(undefined, { url: "https://some.pod/.acl" }))
    );

    const fetchedAcl = await internal_fetchFallbackAcl(sourceDataset, {
      fetch: mockFetch,
    });

    expect(fetchedAcl?.internal_accessTo).toBe("https://some.pod/");
    expect(fetchedAcl?.internal_resourceInfo.fetchedFrom).toBe(
      "https://some.pod/.acl"
    );
    expect(mockFetch.mock.calls).toHaveLength(2);
    expect(mockFetch.mock.calls[0][0]).toBe("https://some.pod/");
    expect(mockFetch.mock.calls[1][0]).toBe("https://some.pod/.acl");
  });

  it("calls the included fetcher by default", async () => {
    const sourceDataset = {
      internal_resourceInfo: {
        fetchedFrom: "https://some.pod/resource",
        isLitDataset: true,
        unstable_aclUrl: "https://some.pod/resource.acl",
      },
    };
    const mockedFetcher = jest.requireMock("../fetcher.ts") as {
      fetch: jest.Mock<
        ReturnType<typeof window.fetch>,
        [RequestInfo, RequestInit?]
      >;
    };

    await internal_fetchFallbackAcl(sourceDataset);

    expect(mockedFetcher.fetch.mock.calls).toHaveLength(1);
    expect(mockedFetcher.fetch.mock.calls[0][0]).toBe("https://some.pod/");
  });

  it("travels up multiple levels if no ACL was found on the levels in between", async () => {
    const sourceDataset = {
      internal_resourceInfo: {
        fetchedFrom: "https://some.pod/with-acl/without-acl/resource",
        isLitDataset: true,
        // If no ACL IRI is given, the user does not have Control Access,
        // in which case we wouldn't be able to reliably determine the effective ACL.
        // Hence, the function requires the given LitDataset to have one known:
        unstable_aclUrl:
          "https://arbitrary.pod/with-acl/without-acl/resource.acl",
      },
    };
    const mockFetch = jest.fn(window.fetch).mockReturnValueOnce(
      Promise.resolve(
        mockResponse("", {
          headers: {
            Link: '<.acl>; rel="acl"',
          },
          url: "https://some.pod/with-acl/without-acl/",
        })
      )
    );
    mockFetch.mockReturnValueOnce(
      Promise.resolve(
        mockResponse("ACL not found", {
          status: 404,
          url: "https://some.pod/with-acl/without-acl/.acl",
        })
      )
    );
    mockFetch.mockReturnValueOnce(
      Promise.resolve(
        mockResponse("", {
          headers: {
            Link: '<.acl>; rel="acl"',
          },
          url: "https://some.pod/with-acl/",
        })
      )
    );
    mockFetch.mockReturnValueOnce(
      Promise.resolve(
        mockResponse(undefined, { url: "https://some.pod/with-acl/.acl" })
      )
    );

    const fetchedAcl = await internal_fetchFallbackAcl(sourceDataset, {
      fetch: mockFetch,
    });

    expect(fetchedAcl?.internal_accessTo).toBe("https://some.pod/with-acl/");
    expect(fetchedAcl?.internal_resourceInfo.fetchedFrom).toBe(
      "https://some.pod/with-acl/.acl"
    );
    expect(mockFetch.mock.calls).toHaveLength(4);
    expect(mockFetch.mock.calls[0][0]).toBe(
      "https://some.pod/with-acl/without-acl/"
    );
    expect(mockFetch.mock.calls[1][0]).toBe(
      "https://some.pod/with-acl/without-acl/.acl"
    );
    expect(mockFetch.mock.calls[2][0]).toBe("https://some.pod/with-acl/");
    expect(mockFetch.mock.calls[3][0]).toBe("https://some.pod/with-acl/.acl");
  });

  // This happens if the user does not have Control access to that Container, in which case we will
  // not be able to determine the effective ACL:
  it("returns null if one of the Containers on the way up does not advertise an ACL", async () => {
    const sourceDataset = {
      internal_resourceInfo: {
        fetchedFrom:
          "https://some.pod/arbitrary-parent/no-control-access/resource",
        isLitDataset: true,
        // If no ACL IRI is given, the user does not have Control Access,
        // in which case we wouldn't be able to reliably determine the effective ACL.
        // Hence, the function requires the given LitDataset to have one known:
        unstable_aclUrl:
          "https://arbitrary.pod/arbitrary-parent/no-control-access/resource.acl",
      },
    };
    const mockFetch = jest.fn(window.fetch).mockReturnValueOnce(
      Promise.resolve(
        mockResponse(undefined, {
          url: "https://some.pod/arbitrary-parent/no-control-access/",
        })
      )
    );

    const fetchedAcl = await internal_fetchFallbackAcl(sourceDataset, {
      fetch: mockFetch,
    });

    expect(fetchedAcl).toBeNull();
    expect(mockFetch.mock.calls).toHaveLength(1);
    expect(mockFetch.mock.calls[0][0]).toBe(
      "https://some.pod/arbitrary-parent/no-control-access/"
    );
  });

  it("returns null if no ACL could be found for the Containers up to the root of the Pod", async () => {
    const sourceDataset = {
      internal_resourceInfo: {
        fetchedFrom: "https://some.pod/resource",
        isLitDataset: true,
        // If no ACL IRI is given, the user does not have Control Access,
        // in which case we wouldn't be able to reliably determine the effective ACL.
        // Hence, the function requires the given LitDataset to have one known:
        unstable_aclUrl: "https://arbitrary.pod/resource.acl",
      },
    };

    const mockFetch = jest.fn(window.fetch).mockReturnValueOnce(
      Promise.resolve(
        mockResponse("", {
          headers: {
            Link: '<.acl>; rel="acl"',
          },
          url: "https://some.pod",
        })
      )
    );
    mockFetch.mockReturnValueOnce(
      Promise.resolve(
        mockResponse("ACL not found", {
          status: 404,
          url: "https://some.pod/.acl",
        })
      )
    );

    const fetchedAcl = await internal_fetchFallbackAcl(sourceDataset, {
      fetch: mockFetch,
    });

    expect(fetchedAcl).toBeNull();
    expect(mockFetch.mock.calls).toHaveLength(2);
    expect(mockFetch.mock.calls[0][0]).toBe("https://some.pod/");
    expect(mockFetch.mock.calls[1][0]).toBe("https://some.pod/.acl");
  });
});

describe("getResourceAcl", () => {
  it("returns the attached Resource ACL Dataset", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_accessTo: "https://arbitrary.pod/resource",
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
    });
    const litDataset = Object.assign(dataset(), {
      internal_acl: { resourceAcl: aclDataset, fallbackAcl: null },
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource",
        isLitDataset: true,
        unstable_aclUrl: "https://arbitrary.pod/resource.acl",
      },
    });
    expect(unstable_getResourceAcl(litDataset)).toEqual(aclDataset);
  });

  it("returns null if the given Resource does not consider the attached ACL to pertain to it", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_accessTo: "https://arbitrary.pod/resource",
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
    });
    const litDataset = Object.assign(dataset(), {
      internal_acl: { resourceAcl: aclDataset, fallbackAcl: null },
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource",
        isLitDataset: true,
        unsafe_aclUrl: "https://arbitrary.pod/other-resource.acl",
      },
    });
    expect(unstable_getResourceAcl(litDataset)).toBeNull();
  });

  it("returns null if the attached ACL does not pertain to the given Resource", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_accessTo: "https://arbitrary.pod/other-resource",
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
    });
    const litDataset = Object.assign(dataset(), {
      internal_acl: { resourceAcl: aclDataset, fallbackAcl: null },
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource",
        isLitDataset: true,
        unsafe_aclUrl: "https://arbitrary.pod/resource.acl",
      },
    });
    expect(unstable_getResourceAcl(litDataset)).toBeNull();
  });

  it("returns null if the given LitDataset does not have a Resource ACL attached", () => {
    const litDataset = Object.assign(dataset(), {
      internal_acl: { fallbackAcl: null, resourceAcl: null },
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource",
        isLitDataset: true,
      },
    });
    expect(unstable_getResourceAcl(litDataset)).toBeNull();
  });
});

describe("getFallbackAcl", () => {
  it("returns the attached Fallback ACL Dataset", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_accessTo: "https://arbitrary.pod/",
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/.acl",
        isLitDataset: true,
      },
    });
    const litDataset = Object.assign(dataset(), {
      internal_acl: { fallbackAcl: aclDataset, resourceAcl: null },
    });
    expect(unstable_getFallbackAcl(litDataset)).toEqual(aclDataset);
  });

  it("returns null if the given LitDataset does not have a Fallback ACL attached", () => {
    const litDataset = Object.assign(dataset(), {
      internal_acl: { fallbackAcl: null, resourceAcl: null },
    });
    expect(unstable_getFallbackAcl(litDataset)).toBeNull();
  });
});

describe("createAcl", () => {
  it("creates a new empty ACL", () => {
    const litDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://some.pod/container/resource",
        isLitDataset: true,
        unstable_aclUrl: "https://some.pod/container/resource.acl",
      },
      internal_acl: { fallbackAcl: null, resourceAcl: null },
    });

    const resourceAcl = unstable_createAcl(litDataset);

    const resourceAclQuads = Array.from(resourceAcl);
    expect(resourceAclQuads).toHaveLength(0);
    expect(resourceAcl.internal_accessTo).toBe(
      "https://some.pod/container/resource"
    );
    expect(resourceAcl.internal_resourceInfo.fetchedFrom).toBe(
      "https://some.pod/container/resource.acl"
    );
  });
});

describe("createAclFromFallbackAcl", () => {
  it("creates a new ACL including existing default rules as Resource rules", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_accessTo: "https://arbitrary.pod/container/",
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/container/.acl",
        isLitDataset: true,
      },
    });
    const subjectIri = "https://arbitrary.pod/container/.acl#" + Math.random();
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#default"),
        DataFactory.namedNode("https://arbitrary.pod/container/")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agent"),
        DataFactory.namedNode("https://arbitrary.pod/profileDoc#webId")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Read")
      )
    );
    const litDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/container/resource",
        isLitDataset: true,
        unstable_aclUrl: "https://arbitrary.pod/container/resource.acl",
      },
      internal_acl: { fallbackAcl: aclDataset, resourceAcl: null },
    });

    const resourceAcl = unstable_createAclFromFallbackAcl(litDataset);

    const resourceAclQuads = Array.from(resourceAcl);
    expect(resourceAclQuads).toHaveLength(4);
    expect(resourceAclQuads[3].predicate.value).toBe(
      "http://www.w3.org/ns/auth/acl#accessTo"
    );
    expect(resourceAclQuads[3].object.value).toBe(
      "https://arbitrary.pod/container/resource"
    );
    expect(resourceAcl.internal_accessTo).toBe(
      "https://arbitrary.pod/container/resource"
    );
    expect(resourceAcl.internal_resourceInfo.fetchedFrom).toBe(
      "https://arbitrary.pod/container/resource.acl"
    );
  });

  it("does not copy over Resource rules from the fallback ACL", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_accessTo: "https://arbitrary.pod/container/",
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/container/.acl",
        isLitDataset: true,
      },
    });
    const subjectIri = "https://arbitrary.pod/container/.acl#" + Math.random();
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/container/")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agent"),
        DataFactory.namedNode("https://arbitrary.pod/profileDoc#webId")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Read")
      )
    );
    const litDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/container/resource",
        isLitDataset: true,
        unstable_aclUrl: "https://arbitrary.pod/container/resource.acl",
      },
      internal_acl: { fallbackAcl: aclDataset, resourceAcl: null },
    });

    const resourceAcl = unstable_createAclFromFallbackAcl(litDataset);

    const resourceAclQuads = Array.from(resourceAcl);
    expect(resourceAclQuads).toHaveLength(0);
  });
});

describe("getAclRules", () => {
  it("only returns Things that represent ACL Rules", () => {
    const aclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
    });

    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode("https://arbitrary.pod/not-an-acl-rule"),
        DataFactory.namedNode("https://arbitrary.vocab/predicate"),
        DataFactory.namedNode("https://arbitrary.pod/resource#object")
      )
    );

    const agentClassRuleSubjectIri =
      "https://some.pod/resource.acl#agentClassRule";
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(agentClassRuleSubjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(agentClassRuleSubjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(agentClassRuleSubjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agentClass"),
        DataFactory.namedNode("http://xmlns.com/foaf/0.1/Agent")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(agentClassRuleSubjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Append")
      )
    );

    const agentRuleSubjectIri = "https://some.pod/resource.acl#agentRule";
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(agentRuleSubjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(agentRuleSubjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(agentRuleSubjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agent"),
        DataFactory.namedNode("https://arbitrary.pod/profileDoc#webId")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(agentRuleSubjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Read")
      )
    );

    const rules = internal_getAclRules(aclDataset);

    expect(rules).toHaveLength(2);
    expect((rules[0] as ThingPersisted).internal_url).toBe(
      agentClassRuleSubjectIri
    );
    expect((rules[1] as ThingPersisted).internal_url).toBe(agentRuleSubjectIri);
  });

  it("returns Things with multiple `rdf:type`s, as long as at least on type is `acl:Authorization`", () => {
    const aclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
    });

    const ruleWithMultipleTypesSubjectIri =
      "https://some.pod/resource.acl#agentClassRule";
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(ruleWithMultipleTypesSubjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("https://arbitrary.vocab/not-an#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(ruleWithMultipleTypesSubjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(ruleWithMultipleTypesSubjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(ruleWithMultipleTypesSubjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agent"),
        DataFactory.namedNode("https://arbitrary.pod/profileDoc#webId")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(ruleWithMultipleTypesSubjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Append")
      )
    );

    const rules = internal_getAclRules(aclDataset);

    expect(rules).toHaveLength(1);
    expect((rules[0] as ThingPersisted).internal_url).toBe(
      ruleWithMultipleTypesSubjectIri
    );
  });
});

describe("getResourceAclRules", () => {
  it("only returns ACL Rules that apply to a Resource", () => {
    const resourceAclRule1: unstable_AclRule = Object.assign(dataset(), {
      internal_url: "https://arbitrary.pod/resource.acl#rule1",
    });
    resourceAclRule1.add(
      DataFactory.quad(
        DataFactory.namedNode("https://arbitrary.pod/resource.acl#rule1"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource1")
      )
    );

    const defaultAclRule1: unstable_AclRule = Object.assign(dataset(), {
      internal_url: "https://arbitrary.pod/container/.acl#rule2",
    });
    defaultAclRule1.add(
      DataFactory.quad(
        DataFactory.namedNode("https://arbitrary.pod/container/.acl#rule2"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#default"),
        DataFactory.namedNode("https://arbitrary.pod/container1/")
      )
    );

    const resourceAclRule2: unstable_AclRule = Object.assign(dataset(), {
      internal_url: "https://arbitrary.pod/resource.acl#rule3",
    });
    resourceAclRule2.add(
      DataFactory.quad(
        DataFactory.namedNode("https://arbitrary.pod/resource.acl#rule3"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource2")
      )
    );

    const defaultAclRule2: unstable_AclRule = Object.assign(dataset(), {
      internal_url: "https://arbitrary.pod/container/.acl#rule4",
    });
    defaultAclRule2.add(
      DataFactory.quad(
        DataFactory.namedNode("https://arbitrary.pod/container/.acl#rule4"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#default"),
        DataFactory.namedNode("https://arbitrary.pod/container2/")
      )
    );

    const aclRules = [
      resourceAclRule1,
      defaultAclRule1,
      resourceAclRule2,
      defaultAclRule2,
    ];

    const resourceRules = internal_getResourceAclRules(aclRules);

    expect(resourceRules).toEqual([resourceAclRule1, resourceAclRule2]);
  });
});

describe("getResourceAclRulesForResource", () => {
  it("only returns ACL Rules that apply to a given Resource", () => {
    const targetResourceAclRule: unstable_AclRule = Object.assign(dataset(), {
      internal_url: "https://arbitrary.pod/resource.acl#rule1",
    });
    targetResourceAclRule.add(
      DataFactory.quad(
        DataFactory.namedNode("https://arbitrary.pod/resource.acl#rule1"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://some.pod/resource")
      )
    );

    const defaultAclRule: unstable_AclRule = Object.assign(dataset(), {
      internal_url: "https://arbitrary.pod/container/.acl#rule2",
    });
    defaultAclRule.add(
      DataFactory.quad(
        DataFactory.namedNode("https://arbitrary.pod/container/.acl#rule2"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#default"),
        DataFactory.namedNode("https://arbitrary.pod/container/")
      )
    );

    const otherResourceAclRule: unstable_AclRule = Object.assign(dataset(), {
      internal_url: "https://arbitrary.pod/resource.acl#rule3",
    });
    otherResourceAclRule.add(
      DataFactory.quad(
        DataFactory.namedNode("https://arbitrary.pod/resource.acl#rule3"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://some-other.pod/resource")
      )
    );

    const aclRules = [
      targetResourceAclRule,
      defaultAclRule,
      otherResourceAclRule,
    ];

    const resourceRules = internal_getResourceAclRulesForResource(
      aclRules,
      "https://some.pod/resource"
    );

    expect(resourceRules).toEqual([targetResourceAclRule]);
  });
});

describe("getDefaultAclRules", () => {
  it("only returns ACL Rules that are the default for a Container", () => {
    const resourceAclRule1: unstable_AclRule = Object.assign(dataset(), {
      internal_url: "https://arbitrary.pod/resource.acl#rule1",
    });
    resourceAclRule1.add(
      DataFactory.quad(
        DataFactory.namedNode("https://arbitrary.pod/resource.acl#rule1"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource1")
      )
    );

    const defaultAclRule1: unstable_AclRule = Object.assign(dataset(), {
      internal_url: "https://arbitrary.pod/container/.acl#rule2",
    });
    defaultAclRule1.add(
      DataFactory.quad(
        DataFactory.namedNode("https://arbitrary.pod/container/.acl#rule2"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#default"),
        DataFactory.namedNode("https://arbitrary.pod/container1/")
      )
    );

    const resourceAclRule2: unstable_AclRule = Object.assign(dataset(), {
      internal_url: "https://arbitrary.pod/resource.acl#rule3",
    });
    resourceAclRule2.add(
      DataFactory.quad(
        DataFactory.namedNode("https://arbitrary.pod/resource.acl#rule3"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource2")
      )
    );

    const defaultAclRule2: unstable_AclRule = Object.assign(dataset(), {
      internal_url: "https://arbitrary.pod/container/.acl#rule4",
    });
    defaultAclRule2.add(
      DataFactory.quad(
        DataFactory.namedNode("https://arbitrary.pod/container/.acl#rule4"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#default"),
        DataFactory.namedNode("https://arbitrary.pod/container2/")
      )
    );

    const aclRules = [
      resourceAclRule1,
      defaultAclRule1,
      resourceAclRule2,
      defaultAclRule2,
    ];

    const resourceRules = internal_getDefaultAclRules(aclRules);

    expect(resourceRules).toEqual([defaultAclRule1, defaultAclRule2]);
  });
});

describe("getDefaultAclRulesForResource", () => {
  it("only returns ACL Rules that are the default for children of a given Container", () => {
    const resourceAclRule: unstable_AclRule = Object.assign(dataset(), {
      internal_url: "https://arbitrary.pod/resource.acl#rule1",
    });
    resourceAclRule.add(
      DataFactory.quad(
        DataFactory.namedNode("https://arbitrary.pod/resource.acl#rule1"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource")
      )
    );

    const targetDefaultAclRule: unstable_AclRule = Object.assign(dataset(), {
      internal_url: "https://arbitrary.pod/container/.acl#rule2",
    });
    targetDefaultAclRule.add(
      DataFactory.quad(
        DataFactory.namedNode("https://arbitrary.pod/container/.acl#rule2"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#default"),
        DataFactory.namedNode("https://some.pod/container/")
      )
    );

    const otherDefaultAclRule: unstable_AclRule = Object.assign(dataset(), {
      internal_url: "https://arbitrary.pod/container/.acl#rule3",
    });
    otherDefaultAclRule.add(
      DataFactory.quad(
        DataFactory.namedNode("https://arbitrary.pod/container/.acl#rule3"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#default"),
        DataFactory.namedNode("https://some-other.pod/container/")
      )
    );

    const aclRules = [
      resourceAclRule,
      targetDefaultAclRule,
      otherDefaultAclRule,
    ];

    const resourceRules = internal_getDefaultAclRulesForResource(
      aclRules,
      "https://some.pod/container/"
    );

    expect(resourceRules).toEqual([targetDefaultAclRule]);
  });
});

describe("getAccess", () => {
  it("returns true for Access Modes that are granted", () => {
    const subject = "https://arbitrary.pod/profileDoc#webId";

    const mockRule = Object.assign(dataset(), { internal_url: subject });
    mockRule.add(
      DataFactory.quad(
        DataFactory.namedNode(subject),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Read")
      )
    );
    mockRule.add(
      DataFactory.quad(
        DataFactory.namedNode(subject),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Append")
      )
    );
    mockRule.add(
      DataFactory.quad(
        DataFactory.namedNode(subject),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Write")
      )
    );
    mockRule.add(
      DataFactory.quad(
        DataFactory.namedNode(subject),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Control")
      )
    );

    expect(internal_getAccess(mockRule)).toEqual({
      read: true,
      append: true,
      write: true,
      control: true,
    });
  });

  it("returns false for undefined Access Modes", () => {
    const subject = "https://arbitrary.pod/profileDoc#webId";

    const mockRule = Object.assign(dataset(), { internal_url: subject });

    expect(internal_getAccess(mockRule)).toEqual({
      read: false,
      append: false,
      write: false,
      control: false,
    });
  });

  it("infers Append access from Write access", () => {
    const subject = "https://arbitrary.pod/profileDoc#webId";

    const mockRule = Object.assign(dataset(), { internal_url: subject });
    mockRule.add(
      DataFactory.quad(
        DataFactory.namedNode(subject),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Write")
      )
    );

    expect(internal_getAccess(mockRule)).toEqual({
      read: false,
      append: true,
      write: true,
      control: false,
    });
  });
});

describe("combineAccessModes", () => {
  it("returns true for Access Modes that are true in any of the given Access Mode sets", () => {
    const modes: unstable_Access[] = [
      { read: false, append: false, write: false, control: false },
      { read: true, append: false, write: false, control: false },
      { read: false, append: true, write: false, control: false },
      { read: false, append: true, write: true, control: false },
      { read: false, append: false, write: false, control: true },
    ];

    expect(internal_combineAccessModes(modes)).toEqual({
      read: true,
      append: true,
      write: true,
      control: true,
    });
  });

  it("returns false for Access Modes that are false in all of the given Access Mode sets", () => {
    const modes: unstable_Access[] = [
      { read: false, append: false, write: false, control: false },
      { read: false, append: false, write: false, control: false },
      { read: false, append: false, write: false, control: false },
    ];

    expect(internal_combineAccessModes(modes)).toEqual({
      read: false,
      append: false,
      write: false,
      control: false,
    });
  });

  it("returns false for all Modes if no Access Modes were given", () => {
    expect(internal_combineAccessModes([])).toEqual({
      read: false,
      append: false,
      write: false,
      control: false,
    });
  });

  it("infers Append access from Write access", () => {
    const modes: unstable_Access[] = [
      { read: false, append: false, write: false, control: false },
      { read: false, append: false, write: true, control: false } as any,
    ];

    expect(internal_combineAccessModes(modes)).toEqual({
      read: false,
      append: true,
      write: true,
      control: false,
    });
  });
});

describe("removeEmptyAclRules", () => {
  it("removes rules that do not apply to anyone", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
    });
    const subjectIri = "https://arbitrary.pod/resource.acl#emptyRule";
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Read")
      )
    );

    const updatedDataset = internal_removeEmptyAclRules(aclDataset);

    expect(Array.from(updatedDataset)).toEqual([]);
  });

  it("does not modify the input LitDataset", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
    });
    const subjectIri = "https://arbitrary.pod/resource.acl#emptyRule";
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Read")
      )
    );

    const updatedDataset = internal_removeEmptyAclRules(aclDataset);

    expect(Array.from(updatedDataset)).toHaveLength(0);
    expect(Array.from(aclDataset)).toHaveLength(3);
  });

  it("removes rules that do not set any Access Modes", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
    });
    const subjectIri = "https://arbitrary.pod/resource.acl#emptyRule";
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agent"),
        DataFactory.namedNode("https://arbitrary.pod/profileDoc#webId")
      )
    );

    const updatedDataset = internal_removeEmptyAclRules(aclDataset);

    expect(Array.from(updatedDataset)).toEqual([]);
  });

  it("removes rules that do not have target Resources to which they apply", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
    });
    const subjectIri = "https://arbitrary.pod/resource.acl#emptyRule";
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agent"),
        DataFactory.namedNode("https://arbitrary.pod/profileDoc#webId")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource")
      )
    );

    const updatedDataset = internal_removeEmptyAclRules(aclDataset);

    expect(Array.from(updatedDataset)).toEqual([]);
  });

  it("removes rules that specify an acl:origin but not in combination with an Agent, Agent Group or Agent Class", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
    });
    const subjectIri = "https://arbitrary.pod/resource.acl#emptyRule";
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Read")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#origin"),
        DataFactory.namedNode("https://arbitrary.origin")
      )
    );

    const updatedDataset = internal_removeEmptyAclRules(aclDataset);

    expect(Array.from(updatedDataset)).toEqual([]);
  });

  it("does not remove Rules that are also something other than an ACL Rule", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
    });
    const subjectIri = "https://arbitrary.pod/resource.acl#rule";
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("https://arbitrary.vocab/not/an/Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Read")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agent"),
        DataFactory.namedNode("https://arbitrary.pod/profileDoc#webId")
      )
    );

    const updatedDataset = internal_removeEmptyAclRules(aclDataset);

    expect(Array.from(updatedDataset)).toEqual(Array.from(aclDataset));
  });

  it("does not remove Things that are Rules but also have other Quads", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
    });
    const subjectIri = "https://arbitrary.pod/resource.acl#rule";
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("https://arbitrary.vocab/predicate"),
        DataFactory.literal("Arbitrary non-ACL value")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Read")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agent"),
        DataFactory.namedNode("https://arbitrary.pod/profileDoc#webId")
      )
    );

    const updatedDataset = internal_removeEmptyAclRules(aclDataset);

    expect(Array.from(updatedDataset)).toEqual(Array.from(aclDataset));
  });

  it("does not remove Rules that apply to a Container's child Resources", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/container/.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/container/",
    });
    const subjectIri = "https://arbitrary.pod/container/.acl#rule";
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#default"),
        DataFactory.namedNode("https://arbitrary.pod/container/")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Read")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agent"),
        DataFactory.namedNode("https://arbitrary.pod/profileDoc#webId")
      )
    );

    const updatedDataset = internal_removeEmptyAclRules(aclDataset);

    expect(Array.from(updatedDataset)).toEqual(Array.from(aclDataset));
  });

  it("does not remove Rules that apply to an Agent", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
    });
    const subjectIri = "https://arbitrary.pod/resource.acl#rule";
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Read")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agent"),
        DataFactory.namedNode("https://arbitrary.pod/profileDoc#webId")
      )
    );

    const updatedDataset = internal_removeEmptyAclRules(aclDataset);

    expect(Array.from(updatedDataset)).toEqual(Array.from(aclDataset));
  });

  it("does not remove Rules that apply to an Agent Group", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
    });
    const subjectIri = "https://arbitrary.pod/resource.acl#rule";
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Read")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agentGroup"),
        DataFactory.namedNode("https://arbitrary.pod/groups#colleagues")
      )
    );

    const updatedDataset = internal_removeEmptyAclRules(aclDataset);

    expect(Array.from(updatedDataset)).toEqual(Array.from(aclDataset));
  });

  it("does not remove Rules that apply to an Agent Class", () => {
    const aclDataset: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
    });
    const subjectIri = "https://arbitrary.pod/resource.acl#rule";
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode(
          "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        ),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#accessTo"),
        DataFactory.namedNode("https://arbitrary.pod/resource")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Read")
      )
    );
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agentClass"),
        DataFactory.namedNode("http://xmlns.com/foaf/0.1/Agent")
      )
    );

    const updatedDataset = internal_removeEmptyAclRules(aclDataset);

    expect(Array.from(updatedDataset)).toEqual(Array.from(aclDataset));
  });
});

describe("saveAclFor", () => {
  it("calls the included fetcher by default", async () => {
    const mockedFetcher = jest.requireMock("../fetcher.ts") as {
      fetch: jest.Mock<
        ReturnType<typeof window.fetch>,
        [RequestInfo, RequestInit?]
      >;
    };
    const withResourceInfo = {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource",
        isLitDataset: true,
        unstable_aclUrl: "https://arbitrary.pod/resource.acl",
      },
    };
    const aclResource: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
    });

    await unstable_saveAclFor(withResourceInfo, aclResource);

    expect(mockedFetcher.fetch.mock.calls).toHaveLength(1);
  });

  it("uses the given fetcher if provided", async () => {
    const mockFetch = jest
      .fn(window.fetch)
      .mockReturnValue(Promise.resolve(new Response()));
    const withResourceInfo = {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource",
        isLitDataset: true,
        unstable_aclUrl: "https://arbitrary.pod/resource.acl",
      },
    };
    const aclResource: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
    });

    await unstable_saveAclFor(withResourceInfo, aclResource, {
      fetch: mockFetch,
    });

    expect(mockFetch.mock.calls).toHaveLength(1);
  });

  it("returns a meaningful error when the server returns a 403", async () => {
    const mockFetch = jest
      .fn(window.fetch)
      .mockReturnValue(
        Promise.resolve(new Response("Not allowed", { status: 403 }))
      );
    const withResourceInfo = {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource",
        isLitDataset: true,
        unstable_aclUrl: "https://arbitrary.pod/resource.acl",
      },
    };
    const aclResource: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
    });

    const fetchPromise = unstable_saveAclFor(withResourceInfo, aclResource, {
      fetch: mockFetch,
    });

    await expect(fetchPromise).rejects.toThrow(
      new Error("Storing the Resource failed: 403 Forbidden.")
    );
  });

  it("marks the stored ACL as applying to the given Resource", async () => {
    const mockFetch = jest
      .fn(window.fetch)
      .mockReturnValue(Promise.resolve(new Response()));
    const withResourceInfo = {
      internal_resourceInfo: {
        fetchedFrom: "https://some.pod/resource",
        isLitDataset: true,
        unstable_aclUrl: "https://arbitrary.pod/resource.acl",
      },
    };
    const aclResource: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://some-other.pod/resource",
    });

    const savedAcl = await unstable_saveAclFor(withResourceInfo, aclResource, {
      fetch: mockFetch,
    });

    expect(savedAcl.internal_accessTo).toBe("https://some.pod/resource");
  });

  it("sends a PATCH if the ACL contains a ChangeLog and was originally fetched from the same location", async () => {
    const mockFetch = jest
      .fn(window.fetch)
      .mockReturnValue(Promise.resolve(new Response()));
    const withResourceInfo = {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource",
        isLitDataset: true,
        unstable_aclUrl: "https://arbitrary.pod/resource.acl",
      },
    };
    const aclResource: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
      internal_changeLog: {
        additions: [],
        deletions: [],
      },
    });

    await unstable_saveAclFor(withResourceInfo, aclResource, {
      fetch: mockFetch,
    });

    expect(mockFetch.mock.calls[0][1]?.method).toBe("PATCH");
  });

  it("sends a PUT if the ACL contains a ChangeLog but was originally fetched from a different location", async () => {
    const mockFetch = jest
      .fn(window.fetch)
      .mockReturnValue(Promise.resolve(new Response()));
    const withResourceInfo = {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary.pod/resource",
        isLitDataset: true,
        unstable_aclUrl: "https://arbitrary.pod/resource.acl",
      },
    };
    const aclResource: unstable_AclDataset = Object.assign(dataset(), {
      internal_resourceInfo: {
        fetchedFrom: "https://arbitrary-other.pod/resource.acl",
        isLitDataset: true,
      },
      internal_accessTo: "https://arbitrary.pod/resource",
      internal_changeLog: {
        additions: [],
        deletions: [],
      },
    });

    await unstable_saveAclFor(withResourceInfo, aclResource, {
      fetch: mockFetch,
    });

    expect(mockFetch.mock.calls[0][1]?.method).toBe("PUT");
  });
});

describe("deleteAclFor", () => {
  it("calls the included fetcher by default", async () => {
    const mockedFetcher = jest.requireMock("../fetcher.ts") as {
      fetch: jest.Mock<
        ReturnType<typeof window.fetch>,
        [RequestInfo, RequestInit?]
      >;
    };
    const mockResource: WithResourceInfo & unstable_WithAccessibleAcl = {
      internal_resourceInfo: {
        fetchedFrom: "https://some.pod/resource",
        isLitDataset: false,
        unstable_aclUrl: "https://some.pod/resource.acl",
      },
    };

    await unstable_deleteAclFor(mockResource);

    expect(mockedFetcher.fetch.mock.calls).toEqual([
      [
        "https://some.pod/resource.acl",
        {
          method: "DELETE",
        },
      ],
    ]);
  });

  it("uses the given fetcher if provided", async () => {
    const mockFetch = jest
      .fn(window.fetch)
      .mockReturnValue(Promise.resolve(new Response()));

    const mockResource: WithResourceInfo & unstable_WithAccessibleAcl = {
      internal_resourceInfo: {
        fetchedFrom: "https://some.pod/resource",
        isLitDataset: false,
        unstable_aclUrl: "https://some.pod/resource.acl",
      },
    };

    await unstable_deleteAclFor(mockResource, { fetch: mockFetch });

    expect(mockFetch.mock.calls).toEqual([
      [
        "https://some.pod/resource.acl",
        {
          method: "DELETE",
        },
      ],
    ]);
  });

  it("returns the input Resource without a Resource ACL", async () => {
    const mockFetch = jest
      .fn(window.fetch)
      .mockReturnValue(Promise.resolve(new Response()));

    const mockResource: WithResourceInfo & unstable_WithAccessibleAcl = {
      internal_resourceInfo: {
        fetchedFrom: "https://some.pod/resource",
        isLitDataset: false,
        unstable_aclUrl: "https://some.pod/resource.acl",
      },
    };

    const savedResource = await unstable_deleteAclFor(mockResource, {
      fetch: mockFetch,
    });

    expect(savedResource.acl.resourceAcl).toBeNull();
  });

  it("returns a meaningful error when the server returns a 403", async () => {
    const mockFetch = jest
      .fn(window.fetch)
      .mockReturnValue(
        Promise.resolve(new Response("Not allowed", { status: 403 }))
      );

    const mockResource: WithResourceInfo & unstable_WithAccessibleAcl = {
      internal_resourceInfo: {
        fetchedFrom: "https://some.pod/resource",
        isLitDataset: false,
        unstable_aclUrl: "https://some.pod/resource.acl",
      },
    };

    const fetchPromise = unstable_deleteAclFor(mockResource, {
      fetch: mockFetch,
    });

    await expect(fetchPromise).rejects.toThrow(
      new Error("Deleting the ACL failed: 403 Forbidden.")
    );
  });

  it("returns a meaningful error when the server returns a 404", async () => {
    const mockFetch = jest
      .fn(window.fetch)
      .mockReturnValue(
        Promise.resolve(new Response("Not found", { status: 404 }))
      );

    const mockResource: WithResourceInfo & unstable_WithAccessibleAcl = {
      internal_resourceInfo: {
        fetchedFrom: "https://some.pod/resource",
        isLitDataset: false,
        unstable_aclUrl: "https://some.pod/resource.acl",
      },
    };

    const fetchPromise = unstable_deleteAclFor(mockResource, {
      fetch: mockFetch,
    });

    await expect(fetchPromise).rejects.toThrow(
      new Error("Deleting the ACL failed: 404 Not Found.")
    );
  });
});
