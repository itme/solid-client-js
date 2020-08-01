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
import { DataFactory } from "n3";
import { dataset } from "@rdfjs/dataset";
import {
  unstable_getPublicResourceAccess,
  unstable_getPublicDefaultAccess,
  unstable_getPublicAccess,
} from "./class";
import {
  LitDataset,
  WithResourceInfo,
  IriString,
  unstable_Access,
  unstable_AclDataset,
  unstable_WithAcl,
} from "../interfaces";

function addAclRuleQuads(
  aclDataset: LitDataset & WithResourceInfo,
  resource: IriString,
  access: unstable_Access,
  type: "resource" | "default",
  agentClass:
    | "http://xmlns.com/foaf/0.1/Agent"
    | "http://www.w3.org/ns/auth/acl#AuthenticatedAgent"
): unstable_AclDataset {
  const subjectIri =
    resource + "#" + encodeURIComponent(agentClass) + Math.random();
  aclDataset.add(
    DataFactory.quad(
      DataFactory.namedNode(subjectIri),
      DataFactory.namedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
      DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Authorization")
    )
  );
  aclDataset.add(
    DataFactory.quad(
      DataFactory.namedNode(subjectIri),
      DataFactory.namedNode(
        type === "resource"
          ? "http://www.w3.org/ns/auth/acl#accessTo"
          : "http://www.w3.org/ns/auth/acl#default"
      ),
      DataFactory.namedNode(resource)
    )
  );
  aclDataset.add(
    DataFactory.quad(
      DataFactory.namedNode(subjectIri),
      DataFactory.namedNode("http://www.w3.org/ns/auth/acl#agentClass"),
      DataFactory.namedNode(agentClass)
    )
  );
  if (access.read) {
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Read")
      )
    );
  }
  if (access.append) {
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Append")
      )
    );
  }
  if (access.write) {
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Write")
      )
    );
  }
  if (access.control) {
    aclDataset.add(
      DataFactory.quad(
        DataFactory.namedNode(subjectIri),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#mode"),
        DataFactory.namedNode("http://www.w3.org/ns/auth/acl#Control")
      )
    );
  }

  return Object.assign(aclDataset, { internal_accessTo: resource });
}

function addAclDatasetToLitDataset(
  litDataset: LitDataset & WithResourceInfo,
  aclDataset: unstable_AclDataset,
  type: "resource" | "fallback"
): LitDataset & WithResourceInfo & unstable_WithAcl {
  const acl: unstable_WithAcl["internal_acl"] = {
    fallbackAcl: null,
    resourceAcl: null,
    ...(((litDataset as any) as unstable_WithAcl).internal_acl ?? {}),
  };
  if (type === "resource") {
    litDataset.internal_resourceInfo.unstable_aclUrl =
      aclDataset.internal_resourceInfo.fetchedFrom;
    aclDataset.internal_accessTo = litDataset.internal_resourceInfo.fetchedFrom;
    acl.resourceAcl = aclDataset;
  } else if (type === "fallback") {
    acl.fallbackAcl = aclDataset;
  }
  return Object.assign(litDataset, { internal_acl: acl });
}

function getMockDataset(fetchedFrom: IriString): LitDataset & WithResourceInfo {
  return Object.assign(dataset(), {
    internal_resourceInfo: {
      fetchedFrom: fetchedFrom,
      isLitDataset: true,
    },
  });
}

describe("getPublicAccess", () => {
  it("returns the Resource's own applicable ACL rules", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/resource.acl"),
      "https://some.pod/container/resource",
      { read: false, append: false, write: false, control: true },
      "resource",
      "http://xmlns.com/foaf/0.1/Agent"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDataset,
      resourceAcl,
      "resource"
    );

    const access = unstable_getPublicAccess(litDatasetWithAcl);

    expect(access).toEqual({
      read: false,
      append: false,
      write: false,
      control: true,
    });
  });

  it("returns the fallback ACL rules if no Resource ACL LitDataset is available", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const fallbackAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://some.pod/container/",
      { read: false, append: false, write: false, control: true },
      "default",
      "http://xmlns.com/foaf/0.1/Agent"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDataset,
      fallbackAcl,
      "fallback"
    );

    const access = unstable_getPublicAccess(litDatasetWithAcl);

    expect(access).toEqual({
      read: false,
      append: false,
      write: false,
      control: true,
    });
  });

  it("returns null if neither the Resource's own nor a fallback ACL was accessible", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const inaccessibleAcl: unstable_WithAcl = {
      internal_acl: { fallbackAcl: null, resourceAcl: null },
    };
    const litDatasetWithInaccessibleAcl = Object.assign(
      litDataset,
      inaccessibleAcl
    );

    expect(unstable_getPublicAccess(litDatasetWithInaccessibleAcl)).toBeNull();
  });

  it("ignores the fallback ACL rules if a Resource ACL LitDataset is available", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/resource.acl"),
      "https://some.pod/container/resource",
      { read: true, append: false, write: false, control: false },
      "resource",
      "http://xmlns.com/foaf/0.1/Agent"
    );
    const fallbackAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://some.pod/container/",
      { read: false, append: false, write: false, control: true },
      "default",
      "http://xmlns.com/foaf/0.1/Agent"
    );
    const litDatasetWithJustResourceAcl = addAclDatasetToLitDataset(
      litDataset,
      resourceAcl,
      "resource"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDatasetWithJustResourceAcl,
      fallbackAcl,
      "fallback"
    );

    const access = unstable_getPublicAccess(litDatasetWithAcl);

    expect(access).toEqual({
      read: true,
      append: false,
      write: false,
      control: false,
    });
  });

  it("ignores default ACL rules from the Resource's own ACL LitDataset", () => {
    const litDataset = getMockDataset("https://some.pod/container/");
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://some.pod/container/",
      { read: true, append: false, write: false, control: false },
      "resource",
      "http://xmlns.com/foaf/0.1/Agent"
    );
    const resourceAclWithDefaultRules = addAclRuleQuads(
      resourceAcl,
      "https://some.pod/container/",
      { read: false, append: false, write: false, control: true },
      "default",
      "http://xmlns.com/foaf/0.1/Agent"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDataset,
      resourceAclWithDefaultRules,
      "resource"
    );

    const access = unstable_getPublicAccess(litDatasetWithAcl);

    expect(access).toEqual({
      read: true,
      append: false,
      write: false,
      control: false,
    });
  });

  it("ignores Resource ACL rules from the fallback ACL LitDataset", () => {
    const litDataset = getMockDataset("https://some.pod/container/resource");
    const fallbackAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://some.pod/container/",
      { read: true, append: false, write: false, control: false },
      "resource",
      "http://xmlns.com/foaf/0.1/Agent"
    );
    const fallbackAclWithDefaultRules = addAclRuleQuads(
      fallbackAcl,
      "https://some.pod/container/",
      { read: false, append: false, write: false, control: true },
      "default",
      "http://xmlns.com/foaf/0.1/Agent"
    );
    const litDatasetWithAcl = addAclDatasetToLitDataset(
      litDataset,
      fallbackAclWithDefaultRules,
      "fallback"
    );

    const access = unstable_getPublicAccess(litDatasetWithAcl);

    expect(access).toEqual({
      read: false,
      append: false,
      write: false,
      control: true,
    });
  });
});

describe("getPublicResourceAccess", () => {
  it("returns the applicable Access Modes for the Agent Class foaf:Agent", () => {
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/resource.acl"),
      "https://arbitrary.pod/resource",
      { read: true, append: false, write: false, control: true },
      "resource",
      "http://xmlns.com/foaf/0.1/Agent"
    );

    const publicAccess = unstable_getPublicResourceAccess(resourceAcl);

    expect(publicAccess).toEqual({
      read: true,
      append: false,
      write: false,
      control: true,
    });
  });

  it("combines Access Modes defined for the Agent Class foaf:Agent in separate rules", () => {
    let resourceAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/resource.acl"),
      "https://arbitrary.pod/resource",
      { read: true, append: false, write: false, control: false },
      "resource",
      "http://xmlns.com/foaf/0.1/Agent"
    );
    resourceAcl = addAclRuleQuads(
      resourceAcl,
      "https://arbitrary.pod/resource",
      { read: false, append: true, write: false, control: false },
      "resource",
      "http://xmlns.com/foaf/0.1/Agent"
    );

    const agentAccess = unstable_getPublicResourceAccess(resourceAcl);

    expect(agentAccess).toEqual({
      read: true,
      append: true,
      write: false,
      control: false,
    });
  });

  it("returns false for all Access Modes if there are no ACL rules for the Agent Class foaf:Agent", () => {
    const resourceAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/resource.acl"),
      "https://arbitrary.pod/resource",
      { read: true, append: false, write: false, control: false },
      "resource",
      "http://www.w3.org/ns/auth/acl#AuthenticatedAgent"
    );

    const agentAccess = unstable_getPublicResourceAccess(resourceAcl);

    expect(agentAccess).toEqual({
      read: false,
      append: false,
      write: false,
      control: false,
    });
  });

  it("ignores ACL rules that apply to a different Agent Class", () => {
    let resourceAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/resource.acl"),
      "https://arbitrary.pod/resource",
      { read: true, append: false, write: false, control: false },
      "resource",
      "http://www.w3.org/ns/auth/acl#AuthenticatedAgent"
    );
    resourceAcl = addAclRuleQuads(
      resourceAcl,
      "https://arbitrary.pod/resource",
      { read: false, append: true, write: false, control: false },
      "resource",
      "http://xmlns.com/foaf/0.1/Agent"
    );

    const agentAccess = unstable_getPublicResourceAccess(resourceAcl);

    expect(agentAccess).toEqual({
      read: false,
      append: true,
      write: false,
      control: false,
    });
  });

  it("ignores ACL rules that apply to a different Resource", () => {
    let resourceAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/resource.acl"),
      "https://some-other.pod/resource",
      { read: true, append: false, write: false, control: false },
      "resource",
      "http://xmlns.com/foaf/0.1/Agent"
    );
    resourceAcl = addAclRuleQuads(
      resourceAcl,
      "https://some.pod/resource",
      { read: false, append: true, write: false, control: false },
      "resource",
      "http://xmlns.com/foaf/0.1/Agent"
    );

    const agentAccess = unstable_getPublicResourceAccess(resourceAcl);

    expect(agentAccess).toEqual({
      read: false,
      append: true,
      write: false,
      control: false,
    });
  });
});

describe("getPublicDefaultAccess", () => {
  it("returns the applicable Access Modes for the Agent Class foaf:Agent", () => {
    const containerAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/container/.acl"),
      "https://arbitrary.pod/container/",
      { read: true, append: false, write: false, control: true },
      "default",
      "http://xmlns.com/foaf/0.1/Agent"
    );

    const agentAccess = unstable_getPublicDefaultAccess(containerAcl);

    expect(agentAccess).toEqual({
      read: true,
      append: false,
      write: false,
      control: true,
    });
  });

  it("combines Access Modes defined for the Agent Class foaf:Agent in separate rules", () => {
    let containerAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/container/.acl"),
      "https://arbitrary.pod/container/",
      { read: true, append: false, write: false, control: false },
      "default",
      "http://xmlns.com/foaf/0.1/Agent"
    );
    containerAcl = addAclRuleQuads(
      containerAcl,
      "https://arbitrary.pod/container/",
      { read: false, append: true, write: false, control: false },
      "default",
      "http://xmlns.com/foaf/0.1/Agent"
    );

    const agentAccess = unstable_getPublicDefaultAccess(containerAcl);

    expect(agentAccess).toEqual({
      read: true,
      append: true,
      write: false,
      control: false,
    });
  });

  it("returns false for all Access Modes if there are no ACL rules for the Agent Class foaf:Agent", () => {
    const containerAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/container/.acl"),
      "https://arbitrary.pod/container/",
      { read: true, append: false, write: false, control: false },
      "default",
      "http://www.w3.org/ns/auth/acl#AuthenticatedAgent"
    );

    const agentAccess = unstable_getPublicDefaultAccess(containerAcl);

    expect(agentAccess).toEqual({
      read: false,
      append: false,
      write: false,
      control: false,
    });
  });

  it("ignores ACL rules that apply to a different Agent Class", () => {
    let containerAcl = addAclRuleQuads(
      getMockDataset("https://arbitrary.pod/container/.acl"),
      "https://arbitrary.pod/container/",
      { read: true, append: false, write: false, control: false },
      "default",
      "http://www.w3.org/ns/auth/acl#AuthenticatedAgent"
    );
    containerAcl = addAclRuleQuads(
      containerAcl,
      "https://arbitrary.pod/container/",
      { read: false, append: true, write: false, control: false },
      "default",
      "http://xmlns.com/foaf/0.1/Agent"
    );

    const agentAccess = unstable_getPublicDefaultAccess(containerAcl);

    expect(agentAccess).toEqual({
      read: false,
      append: true,
      write: false,
      control: false,
    });
  });

  it("ignores ACL rules that apply to a different Resource", () => {
    let containerAcl = addAclRuleQuads(
      getMockDataset("https://some.pod/container/.acl"),
      "https://some-other.pod/container/",
      { read: true, append: false, write: false, control: false },
      "default",
      "http://xmlns.com/foaf/0.1/Agent"
    );
    containerAcl = addAclRuleQuads(
      containerAcl,
      "https://some.pod/container/",
      { read: false, append: true, write: false, control: false },
      "default",
      "http://xmlns.com/foaf/0.1/Agent"
    );

    const agentAccess = unstable_getPublicDefaultAccess(containerAcl);

    expect(agentAccess).toEqual({
      read: false,
      append: true,
      write: false,
      control: false,
    });
  });
});
